import asyncio
import hashlib
import base64
import hmac
import json
import logging
import os
import re
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import quote, unquote, unquote_plus, urlencode, urlparse, urlsplit

import asyncpg
import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse, Response
import jwt
from jwt import PyJWK
from jwt.exceptions import InvalidTokenError
from starlette.requests import Request
import uuid as _uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Configure the root logger. uvicorn's --log-level only configures uvicorn's own
# loggers ("uvicorn", "uvicorn.error", "uvicorn.access"); this module's logger
# propagates to root, which otherwise has no handler and falls back to
# logging.lastResort — WARNING-only, bare message, no timestamp. That is why
# logger.info() calls never appeared and why every line was untimestamped,
# which blocked correlating this service's events against the MCP servers'.
#
# NOTE: LOG_LEVEL must be lowercase. The Dockerfile also passes it to
# `uvicorn --log-level`, whose accepted choices are lowercase-only, so an
# uppercase value fails at container start before this module is imported.
_LOG_LEVEL_RAW: str = os.environ.get("LOG_LEVEL", "info").strip()
_LOG_LEVEL: str = _LOG_LEVEL_RAW.upper()
# uvicorn accepts "trace", which has no stdlib equivalent; treat it as DEBUG so
# setting it does not silently suppress this module's debug lines.
if _LOG_LEVEL == "TRACE":
    _LOG_LEVEL = "DEBUG"
_LOG_LEVEL_UNRECOGNISED: bool = _LOG_LEVEL not in logging.getLevelNamesMapping()
if _LOG_LEVEL_UNRECOGNISED:
    _LOG_LEVEL = "INFO"

# Timestamps are UTC with milliseconds to line up with the MCP servers' JSON
# logs, which emit ISO-8601 UTC at millisecond precision. The converter is set
# on this formatter instance rather than on logging.Formatter (a class-wide
# mutation that would retroactively shift uvicorn's own formatters), which also
# keeps the literal "Z" honest: it cannot outlive the converter that earns it.
_formatter = logging.Formatter(
    fmt="%(asctime)s.%(msecs)03dZ %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
_formatter.converter = time.gmtime
_handler = logging.StreamHandler()
_handler.setFormatter(_formatter)

logging.basicConfig(level=_LOG_LEVEL, handlers=[_handler])
# basicConfig is a no-op when root already has a handler (e.g. if the entrypoint
# ever grows --log-config). Assert the level unconditionally so the untimestamped
# WARNING-only regression this block exists to fix cannot silently return.
logging.getLogger().setLevel(_LOG_LEVEL)

logger = logging.getLogger(__name__)

# Emitted after basicConfig — before it, this would itself hit lastResort.
if _LOG_LEVEL_UNRECOGNISED:
    logger.warning(
        "Ignoring unrecognised LOG_LEVEL=%r; defaulting to INFO", _LOG_LEVEL_RAW
    )

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OIDC_ISSUER_URL: str = os.environ["OIDC_ISSUER_URL"]
OIDC_CLIENT_ID: str = os.environ["OIDC_CLIENT_ID"]
OIDC_CLIENT_SECRET: str = os.environ.get("OIDC_CLIENT_SECRET", "").strip()
MONETA_HOSTED_UI_URL: str = os.environ["MONETA_HOSTED_UI_URL"].rstrip("/")
MPASS_CALLBACK_URL: str = os.environ["MPASS_CALLBACK_URL"]

JWKS_URL: str = OIDC_ISSUER_URL.rstrip("/") + "/.well-known/jwks.json"
EXPECTED_ISSUER: str = OIDC_ISSUER_URL.rstrip("/")
OIDC_DISCOVERY_URL: str = OIDC_ISSUER_URL.rstrip("/") + "/.well-known/openid-configuration"

if not OIDC_CLIENT_SECRET:
    logger.warning(
        "OIDC_CLIENT_SECRET is empty — operating in public-client mode. "
        "Refresh-token requests will be sent to the IdP without a client_secret. "
        "Set OIDC_CLIENT_SECRET only if the IdP requires confidential-client auth."
    )

# ---------------------------------------------------------------------------
# Central mode (FOSS-609) — opt-in. With CLIENTS_FILE unset or empty, _CLIENTS
# is {} and every route behaves as it does for the per-bundle deployment, where
# oauth2-proxy calls /authorize and /token without client authentication and
# the redirect is checked by domain suffix. With it set, this service is one
# OIDC provider for many registered clients; see README "Central mode".
# ---------------------------------------------------------------------------

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_CLIENT_KEYS = {"client_id", "secret_sha256", "redirect_uris", "post_logout_redirect_uris", "smb_binding"}


def _strict_redirect_uri_ok(uri: str) -> bool:
    """An absolute http(s) URI with a plain host: ASCII with no spaces or
    controls, no backslash, no fragment, no userinfo, no `%` in the authority,
    and no dot segments in the path (also percent-encoded — a browser resolves
    them). This is applied before the exact match, and to every registered URI
    at load, so neither side can hold an ambiguous URI."""
    if not uri or not uri.isascii() or "\\" in uri or "#" in uri:
        return False
    if any(ord(c) <= 0x20 or ord(c) == 0x7F for c in uri):
        return False
    u = urlsplit(uri)
    try:
        u.port
    except ValueError:
        return False
    if u.scheme not in ("https", "http") or not u.hostname or "@" in u.netloc or "%" in u.netloc:
        return False
    return not any(seg in (".", "..") for seg in unquote(u.path).split("/"))


def _parse_clients(doc) -> dict[str, dict]:
    """Validate a static-clients document. Any defect refuses startup."""
    entries = doc.get("clients") if isinstance(doc, dict) else None
    if not isinstance(entries, list) or not entries:
        raise RuntimeError("CLIENTS_FILE: 'clients' must be a non-empty list")
    clients: dict[str, dict] = {}
    for c in entries:
        cid = c.get("client_id") if isinstance(c, dict) else None

        def bad(why: str) -> RuntimeError:
            return RuntimeError(f"CLIENTS_FILE: client {cid!r}: {why}")

        if not isinstance(c, dict) or set(c) != _CLIENT_KEYS:
            raise bad(f"keys must be exactly {sorted(_CLIENT_KEYS)}")
        if not isinstance(cid, str) or not cid or cid in clients:
            raise bad("client_id must be a unique, non-empty string")
        hashes = c["secret_sha256"]
        if not isinstance(hashes, list) or not hashes or not all(
            isinstance(h, str) and _SHA256_HEX.fullmatch(h) for h in hashes
        ):
            raise bad("secret_sha256 must be a non-empty list of lowercase hex SHA-256 digests")
        for key, required in (("redirect_uris", True), ("post_logout_redirect_uris", False)):
            uris = c[key]
            if not isinstance(uris, list) or (required and not uris) or not all(
                isinstance(u, str) and _strict_redirect_uri_ok(u) for u in uris
            ):
                raise bad(f"{key} must be a list of strict absolute http(s) URIs")
        binding = c["smb_binding"]
        if binding is not None and (not isinstance(binding, str) or not binding):
            raise bad("smb_binding must be null or a non-empty corporate_id")
        clients[cid] = c
    return clients


def _load_clients(path: str) -> dict[str, dict]:
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"CLIENTS_FILE {path!r} could not be read: {exc}") from None
    return _parse_clients(doc)


_CLIENTS_FILE: str = os.environ.get("CLIENTS_FILE", "").strip()
_CLIENTS: dict[str, dict] = _load_clients(_CLIENTS_FILE) if _CLIENTS_FILE else {}

REDIS_URL: str = os.environ["REDIS_URL"]
# Central mode sets only the host-only __Host-mpass_flow cookie, so it has no
# use for a cookie domain.
COOKIE_DOMAIN: str = os.environ.get("COOKIE_DOMAIN", "") if _CLIENTS else os.environ["COOKIE_DOMAIN"]
BRIDGE_STATE_TTL: int = 600   # seconds — user has this long to complete QR scan
BRIDGE_CODE_TTL: int = 60    # seconds — oauth2-proxy must exchange the code within this window

# How long oauth2-proxy should treat the issued token as valid. Must match
# OAUTH2_PROXY_COOKIE_EXPIRE so the session never expires before the cookie does.
# Cognito id/access tokens expire in 1h; returning their exp here caused oauth2-proxy
# to attempt a refresh_token grant every hour, which the bridge didn't support.
SESSION_EXPIRES_IN: int = int(os.environ.get("SESSION_COOKIE_MAX_AGE_SECONDS", 604800))

# Optional — when set, /mpass/logout chains through Cognito sign-out.
# When absent, /mpass/logout only clears the oauth2-proxy session.
OIDC_LOGOUT_URI: str = os.environ.get("OIDC_LOGOUT_URI", "")
LOGOUT_REDIRECT_URL: str = os.environ.get("LOGOUT_REDIRECT_URL", "")

# SMB corporate-id enforcement — when set, only Cognito access tokens whose
# custom:corporate_id matches this value are accepted. Empty = disabled.
SMB_CORPORATE_ID: str = os.environ.get("SMB_CORPORATE_ID", "").strip()

# Allow redirect_uri on the same platform domain (any subdomain). The callback
# host is e.g. auth.<platform-domain> → platform suffix is .<platform-domain>,
# so design-mcp.<platform-domain>, docs-mcp.<platform-domain> etc. are all
# accepted.
_CALLBACK_HOST: str = urlparse(MPASS_CALLBACK_URL).netloc
_PLATFORM_DOMAIN_SUFFIX: str = _CALLBACK_HOST.removeprefix("auth")

# Portal URL — where user-facing callback failures redirect. Derived from the
# callback host by stripping the `auth.` subdomain (e.g. auth.local.moneta.dev
# → local.moneta.dev). Override with PORTAL_URL env if the convention differs.
def _derive_portal_url() -> str:
    explicit = os.environ.get("PORTAL_URL", "").strip()
    if explicit:
        return explicit
    parsed = urlparse(MPASS_CALLBACK_URL)
    host = parsed.netloc[len("auth."):] if parsed.netloc.startswith("auth.") else parsed.netloc
    return f"{parsed.scheme}://{host}/"

PORTAL_URL: str = _derive_portal_url()

# ---------------------------------------------------------------------------
# App + Redis
# ---------------------------------------------------------------------------

app = FastAPI(docs_url=None, redoc_url=None)
redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)

# ---------------------------------------------------------------------------
# RSA signing key (Approach A' — see ADR-0007)
# Three sources, in precedence order by _load_signing_key():
# MPASS_SIGNING_KEY_B64, then the MPASS_SIGNING_KEY_GCP_PROJECT / _SECRET pair,
# then — only with MPASS_SIGNING_KEY_ALLOW_EPHEMERAL — a key generated in
# memory (dev only: all issued tokens become invalid on restart, and horizontal
# scaling is not supported in this mode). With none of the three configured,
# startup fails rather than degrading. Only an *absent* source falls through:
# a B64 value that is set but unreadable is fatal, it does not try GCP next.
# Loaded only when LAUNCHPAD_EMAIL_CAPTURE is on. See .env.example for the
# full contract.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Launchpad email capture — feature flag
# ---------------------------------------------------------------------------
# Off by default so this branch is inert on merge. Four things move together and
# MUST NOT be separated:
#
#   1. oauth2-proxy's OIDC_ISSUER_URL / OIDC_JWKS_URL (Cognito vs this service)
#   2. whether this service re-signs the id_token or echoes the IdP's
#   3. whether the email overlay runs at all
#   4. whether launchpad-api is deployed
#
# (1) and (2) are the dangerous pair: oauth2-proxy verifies every id_token
# against whichever JWKS it is pointed at, so re-signing while it still trusts
# Cognito -- or echoing Cognito's token while it trusts us -- means no token
# verifies and nobody can log in to anything. They are driven from this one flag
# for that reason. See docker-compose.yml's oauth2-proxy block.
_EMAIL_CAPTURE_ENABLED: bool = (
    os.environ.get("LAUNCHPAD_EMAIL_CAPTURE", "false").strip().lower()
    in {"1", "true", "yes"}
)


# Ephemeral keys are a local-development affordance only. Guarding on an opt-in
# rather than on an environment name means a deploy that configures no key
# source stops at startup instead of silently degrading, which is the failure
# this guard exists to prevent -- an env-name check would pass on any host whose
# ENVIRONMENT var was also unset.
_EPHEMERAL_SIGNING_KEY_ALLOWED: bool = (
    os.environ.get("MPASS_SIGNING_KEY_ALLOW_EPHEMERAL", "false").strip().lower()
    in {"1", "true", "yes"}
)


def _public_key_fingerprint(public_key) -> str:
    """SHA-256 fingerprint of the public key's DER bytes, hex-encoded.
    Deterministic — the same key always yields the same kid."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:32]


def _decode_signing_key_b64(value: str):
    """Decode MPASS_SIGNING_KEY_B64 into an RSA private key, or raise.

    `value` is base64 (single line) of an unencrypted PEM private key. Base64
    rather than raw PEM because ~10 scripts in this repo do `set -a; source
    .env`, and a multi-line value breaks all of them.

    Fail closed. Every failure here raises: a value that is present but corrupt
    is a configuration error to surface, never a reason to fall through to GCP
    or to an ephemeral key -- not even when MPASS_SIGNING_KEY_ALLOW_EPHEMERAL is
    set. Note this is deliberately stricter than the GCP branch below, which
    does still fall back to ephemeral under that opt-in; the asymmetry is
    intentional in this change, and tightening the GCP branch to match is a
    separate one. Do not "fix" the difference by loosening this side.

    The value never appears in a message or a chained traceback (`from None`) --
    it is the platform's identity signing key.
    """
    try:
        pem = base64.b64decode(value, validate=True)
    except Exception:
        raise RuntimeError(
            "MPASS_SIGNING_KEY_B64 is not valid base64 — refusing to start. "
            "Expected a single-line base64 encoding of an unencrypted PEM RSA "
            "private key, e.g. `openssl genpkey -algorithm RSA -pkeyopt "
            "rsa_keygen_bits:2048 | base64 | tr -d '\\n'`. The value is not "
            "shown here because it is a private key."
        ) from None

    try:
        private_key = serialization.load_pem_private_key(pem, password=None)
    except Exception:
        raise RuntimeError(
            "MPASS_SIGNING_KEY_B64 decoded, but the result is not a readable "
            "unencrypted PEM private key — refusing to start. Encrypted "
            "(passphrase-protected) keys are not supported. The decoded value "
            "is not shown here because it is a private key."
        ) from None

    if not isinstance(private_key, rsa.RSAPrivateKey):
        # An EC or Ed25519 PEM loads fine above and _public_key_fingerprint
        # works on any key type, so without this check startup would succeed and
        # log a plausible kid -- and then _jwks_document()'s .public_numbers().n
        # would raise on the first JWKS fetch. oauth2-proxy gets a 500, nobody
        # can log in to anything, and the service still looks healthy.
        raise RuntimeError(
            "MPASS_SIGNING_KEY_B64 holds a "
            f"{type(private_key).__name__} private key, but this service signs "
            "id_tokens with RS256 and publishes an RSA JWKS — refusing to "
            "start. Generate an RSA key of at least 2048 bits."
        )

    if private_key.key_size < 2048:
        raise RuntimeError(
            f"MPASS_SIGNING_KEY_B64 holds a {private_key.key_size}-bit RSA key; "
            "at least 2048 bits are required — refusing to start."
        )

    return private_key


def _load_signing_key():
    """Load the RSA signing key. Called only when _EMAIL_CAPTURE_ENABLED.

    Precedence:
      1. MPASS_SIGNING_KEY_B64 non-empty          -> use it
      2. else GCP project AND secret non-empty    -> GCP Secret Manager
      3. else MPASS_SIGNING_KEY_ALLOW_EPHEMERAL   -> generate in memory (dev only)
      4. else                                     -> refuse to start

    "Non-empty after .strip()" is the test throughout, not presence in the
    environment: docker-compose.yml passes `${MPASS_SIGNING_KEY_B64:-}`, so the
    variable is *always* in the container environment and empty when
    unconfigured. A `in os.environ` check would make case 1 always win in every
    containerised deployment and kill the stack on decoding "". The GCP vars
    below already use the same empty-means-unset rule.

    Env vars:
      MPASS_SIGNING_KEY_B64          — base64 of an unencrypted PEM RSA private key
      MPASS_SIGNING_KEY_GCP_PROJECT  — GCP project id            (both required
      MPASS_SIGNING_KEY_GCP_SECRET   — secret resource name       for the GCP path)

    Returns: (private_key, kid)
    """
    key_b64 = os.environ.get("MPASS_SIGNING_KEY_B64", "").strip()
    if key_b64:
        private_key = _decode_signing_key_b64(key_b64)
        kid = _public_key_fingerprint(private_key.public_key())
        logger.info(
            "Loaded RSA signing key from MPASS_SIGNING_KEY_B64 (kid=%s)", kid
        )
        return private_key, kid

    project_id = os.environ.get("MPASS_SIGNING_KEY_GCP_PROJECT", "").strip()
    secret_name = os.environ.get("MPASS_SIGNING_KEY_GCP_SECRET", "").strip()

    if project_id and secret_name:
        try:
            from google.cloud import secretmanager
            client = secretmanager.SecretManagerServiceClient()
            resource = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
            response = client.access_secret_version(request={"name": resource})
            private_key = serialization.load_pem_private_key(
                response.payload.data, password=None
            )
            kid = _public_key_fingerprint(private_key.public_key())
            logger.info(
                "Loaded RSA signing key from GCP Secret Manager (project=%s, secret=%s, kid=%s)",
                project_id, secret_name, kid,
            )
            return private_key, kid
        except Exception as exc:
            if _EPHEMERAL_SIGNING_KEY_ALLOWED:
                logger.warning(
                    "Failed to load signing key from GCP Secret Manager "
                    "(project=%s, secret=%s): %s — falling back to ephemeral "
                    "in-memory key because MPASS_SIGNING_KEY_ALLOW_EPHEMERAL is "
                    "set. Sessions will be invalidated on next restart. "
                    "DO NOT run this configuration in staging or production.",
                    project_id, secret_name, exc,
                )
            else:
                logger.error(
                    "Failed to load signing key from GCP Secret Manager "
                    "(project=%s, secret=%s): %s — refusing to start.",
                    project_id, secret_name, exc,
                )
    else:
        logger.warning(
            "No signing key configured (MPASS_SIGNING_KEY_B64 empty, and "
            "MPASS_SIGNING_KEY_GCP_PROJECT / MPASS_SIGNING_KEY_GCP_SECRET not "
            "configured); generating ephemeral in-memory RSA signing key. All "
            "issued tokens will become invalid on the next restart, and "
            "horizontal scaling is not supported in this mode. This is for "
            "local development only."
        )

    if not _EPHEMERAL_SIGNING_KEY_ALLOWED:
        raise RuntimeError(
            "Refusing to start with an ephemeral RSA signing key. "
            "oauth2-proxy verifies every id_token against this service's JWKS, "
            "so a per-process uuid4 kid means every restart forces a re-login "
            "across the whole platform and no second replica can verify the "
            "first's tokens. Set MPASS_SIGNING_KEY_B64 (base64 of an "
            "unencrypted PEM RSA private key; platform.sh --setup generates "
            "one), or set MPASS_SIGNING_KEY_GCP_PROJECT and "
            "MPASS_SIGNING_KEY_GCP_SECRET to use GCP Secret Manager instead "
            "(see dev/docs/deploy-signing-key.md), or set "
            "MPASS_SIGNING_KEY_ALLOW_EPHEMERAL=true for local development."
        )

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = _uuid.uuid4().hex
    return private_key, kid


# Only load a signing key when we are actually the signer. With the feature off
# oauth2-proxy verifies against the IdP directly and this service never signs
# anything, so requiring a signing key would be a deployment burden for a code
# path that does not run.
if _EMAIL_CAPTURE_ENABLED or _CLIENTS:
    _SIGNING_PRIVATE_KEY, _SIGNING_KID = _load_signing_key()
else:
    _SIGNING_PRIVATE_KEY, _SIGNING_KID = None, None

def _jwks_document() -> dict:
    """Public-key JWKS document for oauth2-proxy to verify our re-signed tokens."""
    public_numbers = _SIGNING_PRIVATE_KEY.public_key().public_numbers()
    def _b64url_uint(n: int) -> str:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": _SIGNING_KID,
            "n": _b64url_uint(public_numbers.n),
            "e": _b64url_uint(public_numbers.e),
        }]
    }


MPASS_PROXY_ISSUER_URL: str = os.environ.get(
    "MPASS_PROXY_ISSUER_URL", "http://mpass-auth-proxy:8000"
)

if _CLIENTS:
    # Clients verify iss against this exact string, and __Host- cookies exist
    # only over https, so the in-bundle default is never right centrally.
    _issuer = os.environ.get("MPASS_PROXY_ISSUER_URL", "").strip()
    if not _issuer.startswith("https://") or _issuer.endswith("/"):
        raise RuntimeError(
            "Central mode (CLIENTS_FILE) needs MPASS_PROXY_ISSUER_URL set to this "
            "service's public https origin, with no trailing slash."
        )
    if not OIDC_LOGOUT_URI:
        raise RuntimeError(
            "Central mode (CLIENTS_FILE) needs OIDC_LOGOUT_URI: /logout must end "
            "the IdP session, not only the client's."
        )
    if _EPHEMERAL_SIGNING_KEY_ALLOWED:
        raise RuntimeError(
            "MPASS_SIGNING_KEY_ALLOW_EPHEMERAL is set, and central mode "
            "(CLIENTS_FILE) refuses it: every replica must sign with the one key "
            "the clients verify against. Unset it and configure "
            "MPASS_SIGNING_KEY_B64 or the MPASS_SIGNING_KEY_GCP_* pair."
        )
    if SMB_CORPORATE_ID:
        raise RuntimeError(
            "SMB_CORPORATE_ID is ignored in central mode (CLIENTS_FILE); each "
            "client's smb_binding decides. Unset it rather than leave a setting "
            "that looks enforced and is not."
        )


async def _issue_id_token(idp_id_token: str) -> str:
    """The id_token to hand back to oauth2-proxy.

    With email capture off this is the IdP's token, byte for byte, and
    oauth2-proxy verifies it against the IdP's JWKS. With it on we overlay the
    verified email and re-sign, and oauth2-proxy verifies against ours instead.

    Both halves are driven by the same flag on purpose: signing with one key
    while oauth2-proxy trusts another means no token verifies and nobody can log
    in to any application. Raises EmailOverlayUnavailable, which callers turn
    into a 503."""
    if not _EMAIL_CAPTURE_ENABLED:
        return idp_id_token

    claims = _decode_id_token_claims_unsafe(idp_id_token)
    if claims is None:
        raise ValueError("Corrupt id_token")
    claims = await _apply_email_overlay(claims)
    return _resign_id_token(claims)


def _resign_id_token(claims: dict) -> str:
    """Re-sign an id_token's claims with our RSA key. Replaces iss with our URL.
    Preserves all other claims (sub, aud, email, exp, iat, cognito:username, etc.)."""
    new_claims = dict(claims)
    new_claims["iss"] = MPASS_PROXY_ISSUER_URL
    return jwt.encode(
        new_claims,
        _SIGNING_PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": _SIGNING_KID},
    )


def _decode_id_token_claims_unsafe(id_token: str) -> dict | None:
    """Extract claims from a Cognito-signed id_token without re-verifying.

    Skipping signature verification here is intentional and safe at both call
    sites, because the token's provenance is already trusted:
      - callback path: the signature was verified in `_bridge_callback_impl`
        before the token was stored in Redis;
      - refresh path: the token is a fresh server-to-server response read
        directly from Cognito's token endpoint over TLS.
    We only need the payload to apply the email overlay and re-sign it."""
    try:
        return jwt.decode(id_token, options={"verify_signature": False})
    except InvalidTokenError:
        return None


# ---------------------------------------------------------------------------
# Synthetic email domain. Read from config rather than hardcoded so this
# service and the platform agree on one value: the bundle passes
# ${DEFAULT_EMAIL_DOMAIN}, which is also what the apps and the admin
# provisioning script use.
#
# Unset is fatal rather than defaulted. A wrong or changed value here does not
# degrade the service, it silently re-keys identity: downstream apps provision
# on the email claim, so every user would arrive as a brand-new principal and
# their existing workspaces, documents and issues would be orphaned. That is
# not something to let a missing environment variable decide.
if _EMAIL_CAPTURE_ENABLED and not os.environ.get("LAUNCHPAD_DB_PASSWORD", "").strip():
    # Compose cannot make a required-variable guard conditional -- it
    # interpolates every service regardless of profiles -- so the check lives
    # here. An empty password does not degrade the overlay, it makes every
    # lookup fail, and since the overlay fails closed that is a 503 on every
    # token exchange platform-wide.
    raise RuntimeError(
        "LAUNCHPAD_EMAIL_CAPTURE is on but LAUNCHPAD_DB_PASSWORD is empty. "
        "Set LAUNCHPAD_MPASS_DB_PASSWORD in .env (platform.sh generates it on a "
        "fresh install; existing deployments must add it by hand -- see "
        "dev/docs/launchpad-runbook.md)."
    )

_SYNTHETIC_EMAIL_DOMAIN: str = os.environ.get("SYNTHETIC_EMAIL_DOMAIN", "").strip()
if _EMAIL_CAPTURE_ENABLED and not _SYNTHETIC_EMAIL_DOMAIN:
    raise RuntimeError(
        "SYNTHETIC_EMAIL_DOMAIN is required. It forms the synthetic address "
        "(<synthetic_id>@<domain>) that unverified users are identified by, and "
        "every downstream app keys identity on that claim -- so defaulting it "
        "would silently re-key every user. Set it to the platform's "
        "DEFAULT_EMAIL_DOMAIN."
    )


# Launchpad DB — email overlay (Approach A' — see ADR-0007)
# Looks up the real, verified email for a synthetic <sid>@<domain> claim so
# downstream apps see the real address. DB failure must never break login.
# ---------------------------------------------------------------------------

_LAUNCHPAD_DSN: str = (
    f"postgresql://{os.environ.get('LAUNCHPAD_DB_USER', 'mpass_auth_user')}:"
    f"{os.environ.get('LAUNCHPAD_DB_PASSWORD', '')}@"
    f"{os.environ.get('LAUNCHPAD_DB_HOST', 'postgres')}:"
    f"{os.environ.get('LAUNCHPAD_DB_PORT', '5432')}/"
    f"{os.environ.get('LAUNCHPAD_DB_NAME', 'launchpad')}"
)
_launchpad_pool: asyncpg.Pool | None = None

# Negative cache for pool construction. The overlay runs on every /token call,
# so without this a missing or unreachable launchpad database means a fresh
# create_pool attempt -- and a full connect timeout -- on every login and every
# refresh, platform-wide. One attempt per cooldown window instead.
_LAUNCHPAD_POOL_RETRY_COOLDOWN = timedelta(seconds=30)
_launchpad_pool_failed_at: datetime | None = None
_launchpad_pool_lock = asyncio.Lock()


class EmailOverlayUnavailable(Exception):
    """The launchpad lookup could not be completed.

    Distinct from "this user has no verified email", which is an answer. This
    means we do not know, and callers must fail the request rather than issue a
    token carrying the synthetic address -- downstream apps key identity on that
    address, so guessing makes one human arrive as two different principals.
    """


async def _get_launchpad_pool() -> asyncpg.Pool:
    global _launchpad_pool, _launchpad_pool_failed_at
    if _launchpad_pool is not None:
        return _launchpad_pool

    # Serialised so a login storm after a restart constructs one pool rather
    # than one per concurrent request, each holding up to max_size connections
    # against a Postgres shared with every other app.
    async with _launchpad_pool_lock:
        if _launchpad_pool is not None:
            return _launchpad_pool

        if _launchpad_pool_failed_at is not None:
            since = datetime.now(UTC) - _launchpad_pool_failed_at
            if since < _LAUNCHPAD_POOL_RETRY_COOLDOWN:
                raise EmailOverlayUnavailable(
                    f"launchpad pool unavailable; retry suppressed for another "
                    f"{(_LAUNCHPAD_POOL_RETRY_COOLDOWN - since).total_seconds():.0f}s"
                )

        try:
            _launchpad_pool = await asyncpg.create_pool(
                dsn=_LAUNCHPAD_DSN, min_size=1, max_size=5, command_timeout=5,
            )
        except Exception as exc:
            _launchpad_pool_failed_at = datetime.now(UTC)
            # ERROR, not warning, and once per cooldown window rather than per
            # request: while this is failing every /token exchange and every
            # session refresh returns 503 platform-wide, and /health cannot see
            # it -- it is a static 200 that touches neither the pool nor the IdP.
            logger.error(
                "launchpad pool unavailable — ALL token exchanges and session "
                "refreshes will return 503 until this recovers. %s: %s",
                type(exc).__name__, exc,
            )
            raise
        _launchpad_pool_failed_at = None
        return _launchpad_pool


async def _lookup_real_email(synthetic_id: str) -> str | None:
    """Return the real email for a verified user, or None if there is no
    verified row. Raises on any failure to reach the database — see
    EmailOverlayUnavailable."""
    pool = await _get_launchpad_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT real_email FROM foss_users "
            "WHERE synthetic_id = $1 AND verified = TRUE",
            synthetic_id,
        )
    return row["real_email"] if row else None


async def _apply_email_overlay(claims: dict) -> dict:
    """Normalize the email claim to either a verified real email or the
    synthetic `<sid>@<SYNTHETIC_EMAIL_DOMAIN>`. Cognito's `email` claim is the
    literal string
    `cognito:default_val` for synthetic users — useless downstream — so we
    always replace it. Also stamps `preferred_username` with the synthetic_id
    so apps can recover the stable identifier even when email is real.

    Raises EmailOverlayUnavailable when the lookup cannot be completed. It is
    tempting to swallow that and fall back to the synthetic address, but a
    verified user would then be issued a token identifying them as
    the synthetic address for the duration of the outage, and every app keys
    identity
    on that claim -- so a one-second database hiccup silently turns one human
    into two principals, intermittently. A 503 is recoverable; a split identity
    is not."""
    # cognito:username only. The `sub` fallback that used to sit here mixed two
    # claim namespaces in a single keyspace with nothing recording which one a
    # given row came from, so two users from different claim sources could
    # collide on one synthetic_id -- and foss_users keys on exactly that.
    # mPass-issued Cognito tokens always carry cognito:username, so the
    # fallback bought nothing and risked a cross-user identity mix-up.
    synthetic_id = claims.get("cognito:username")
    if not synthetic_id:
        # Fail closed, like the lookup failure below. Returning `claims`
        # unchanged would forward Cognito's own email claim, which for these
        # users is the literal string `cognito:default_val` -- every app would
        # then key identity on that shared value. A 503 is recoverable; silently
        # merging users is not.
        logger.error(
            "id_token carries no cognito:username claim; refusing to issue a "
            "token rather than forwarding an unusable email claim."
        )
        raise EmailOverlayUnavailable("id_token has no cognito:username claim")
    try:
        real_email = await _lookup_real_email(synthetic_id)
    except EmailOverlayUnavailable:
        raise
    except Exception as exc:
        logger.warning(
            "foss_users lookup failed for sid=%s: %s: %s",
            synthetic_id, type(exc).__name__, exc,
        )
        raise EmailOverlayUnavailable(str(exc)) from exc
    new_claims = dict(claims)
    new_claims["preferred_username"] = synthetic_id
    if real_email:
        new_claims["email"] = real_email
        logger.info("overlay: applied real_email for sid=%s", synthetic_id)
    else:
        new_claims["email"] = f"{synthetic_id}@{_SYNTHETIC_EMAIL_DOMAIN}"
        logger.info("overlay: set synthetic email for sid=%s", synthetic_id)
    return new_claims


# ---------------------------------------------------------------------------
# JWKS cache
# ---------------------------------------------------------------------------

_jwks_cache: dict | None = None
_jwks_fetched_at: datetime | None = None
_JWKS_CACHE_TTL = timedelta(hours=1)

_token_endpoint_cache: str | None = None


async def _get_token_endpoint() -> str:
    # For Cognito, the issuer URL (cognito-idp.<region>.amazonaws.com/<pool>) is
    # NOT where /oauth2/token lives — that's on the OAuth/hosted-UI domain
    # (e.g. <prefix>.auth.<region>.amazoncognito.com/oauth2/token). The discovery
    # doc resolves this correctly across providers.
    global _token_endpoint_cache
    if _token_endpoint_cache is None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(OIDC_DISCOVERY_URL)
            resp.raise_for_status()
            _token_endpoint_cache = resp.json()["token_endpoint"]
        logger.info("OIDC token endpoint discovered: %s", _token_endpoint_cache)
    return _token_endpoint_cache


async def _get_jwks() -> dict:
    global _jwks_cache, _jwks_fetched_at
    now = datetime.now(UTC)
    if _jwks_cache is None or (
        _jwks_fetched_at and (now - _jwks_fetched_at) > _JWKS_CACHE_TTL
    ):
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(JWKS_URL)
            resp.raise_for_status()
            _jwks_cache = resp.json()
            _jwks_fetched_at = now
    return _jwks_cache


def _verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    if not code_verifier:
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return computed == code_challenge


def _clear_bridge_cookie(response: Response) -> Response:
    """Idempotent mpass_bridge cleanup. Called on every /mpass-callback exit
    path (success + failure) so a stale bridge cookie doesn't linger after
    Tab A consumed the Redis state for Tab B's flow."""
    response.delete_cookie("mpass_bridge", domain=COOKIE_DOMAIN, path="/")
    return response


class CorporateIdMismatch(Exception):
    def __init__(self, message: str, reason: str = ""):
        super().__init__(message)
        self.reason = reason


async def _validate_corporate_id(access_token: str) -> None:
    """Decode the Cognito access_token via JWKS and verify corporate claims.
    Raises CorporateIdMismatch on failure. No-op when SMB_CORPORATE_ID is empty."""
    if not SMB_CORPORATE_ID:
        return

    jwks = await _get_jwks()
    header = jwt.get_unverified_header(access_token)
    kid = header.get("kid")
    signing_key = next(
        (k for k in jwks.get("keys", []) if k.get("kid") == kid),
        None,
    )
    if signing_key is None:
        raise CorporateIdMismatch("No JWKS key matching access_token kid")

    claims = jwt.decode(
        access_token,
        PyJWK.from_dict(signing_key).key,
        algorithms=["RS256"],
        options={"verify_aud": False},
        issuer=EXPECTED_ISSUER,
        leeway=60,
    )

    username = claims.get("username", "?")
    # Log `sub` rather than `username`: this line now reaches stdout on every
    # login and every refresh, and `username` is the user's email address when
    # the Cognito pool uses email as an alias attribute. `sub` is opaque, still
    # correlates a session across services, and matches the identifier already
    # used for the auth-code line below.
    logger.info(
        "corporate-id check: sub=%s is_corporate=%r corporate_id=%r expected=%r",
        claims.get("sub", "?"),
        claims.get("custom:is_corporate"),
        claims.get("custom:corporate_id"),
        SMB_CORPORATE_ID,
    )

    if claims.get("client_id") != OIDC_CLIENT_ID:
        raise CorporateIdMismatch(f"user={username} client_id mismatch: {claims.get('client_id')}")
    if claims.get("token_use") != "access":
        raise CorporateIdMismatch(f"user={username} token_use is not 'access': {claims.get('token_use')}")
    if claims.get("custom:is_corporate") != "true":
        raise CorporateIdMismatch(
            f"user={username} Individual (non-corporate) account rejected "
            f"(is_corporate={claims.get('custom:is_corporate')!r})",
            reason="not_corporate",
        )
    if claims.get("custom:corporate_id") != SMB_CORPORATE_ID:
        raise CorporateIdMismatch(
            f"user={username} corporate_id mismatch: got {claims.get('custom:corporate_id')!r}, "
            f"expected {SMB_CORPORATE_ID!r}",
            reason="wrong_organization",
        )


def _portal_redirect_with_error(
    error_code: Literal["expired_flow", "access_denied"],
    reason: str = "",
) -> Response:
    """Graceful user-facing failure — redirect to the portal with a flag the
    landing JS reads and surfaces as a toast. Used when the callback can't
    succeed for a reason the user can act on (no bridge cookie, expired state)
    so they don't see a stark 400 page."""
    params: dict = {"login_error": error_code}
    if reason:
        params["reason"] = reason
    sep = "&" if "?" in PORTAL_URL else "?"
    return RedirectResponse(url=f"{PORTAL_URL}{sep}{urlencode(params)}", status_code=302)


def _moneta_login_url() -> str:
    params = urlencode({
        "client_id": OIDC_CLIENT_ID,
        "client_redirect_url": MPASS_CALLBACK_URL,
        # "signin_option": "qr",
    })
    return f"{MONETA_HOSTED_UI_URL}/users/login?{params}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/.well-known/jwks.json")
async def jwks() -> dict:
    # With email capture off this service does not sign anything -- oauth2-proxy
    # is pointed at the IdP's JWKS instead. Serving an empty or invented key set
    # here would be worse than 404: a misconfigured oauth2-proxy pointed at us
    # would fail verification with no indication why.
    if not (_EMAIL_CAPTURE_ENABLED or _CLIENTS):
        raise HTTPException(
            status_code=404,
            detail=(
                "mpass-auth-proxy is not the token signer: LAUNCHPAD_EMAIL_CAPTURE "
                "is off, so oauth2-proxy must verify against the IdP's JWKS."
            ),
        )
    return _jwks_document()


@app.get("/mpass/login")
async def mpass_login() -> Response:
    if _CLIENTS:  # relative /oauth2 paths assume a co-located oauth2-proxy
        raise HTTPException(status_code=404)
    return RedirectResponse(url="/oauth2/sign_in", status_code=302)


@app.get("/mpass/logout")
async def mpass_logout() -> Response:
    if _CLIENTS:  # central mode: GET /logout
        raise HTTPException(status_code=404)
    if OIDC_LOGOUT_URI and LOGOUT_REDIRECT_URL:
        sep = "&" if "?" in OIDC_LOGOUT_URI else "?"
        cognito_url = (
            f"{OIDC_LOGOUT_URI}"
            f"{sep}client_id={OIDC_CLIENT_ID}"
            f"&logout_uri={LOGOUT_REDIRECT_URL}"
        )
        rd = quote(cognito_url, safe="")
        sign_out_url = f"/oauth2/sign_out?rd={rd}"
    else:
        sign_out_url = "/oauth2/sign_out"

    response = RedirectResponse(url=sign_out_url, status_code=302)
    return _clear_bridge_cookie(response)


@app.get("/authorize")
async def bridge_authorize(request: Request) -> Response:
    if _CLIENTS:
        return await _central_authorize(request)
    state = request.query_params.get("state", "")
    redirect_uri = request.query_params.get("redirect_uri", "")
    code_challenge = request.query_params.get("code_challenge", "")
    code_challenge_method = request.query_params.get("code_challenge_method", "S256")

    if not state or not redirect_uri or not code_challenge:
        return Response(status_code=400, content="Missing required OIDC params")

    if code_challenge_method != "S256":
        return Response(status_code=400, content="Only S256 code_challenge_method is supported")

    parsed = urlparse(redirect_uri)
    if not parsed.netloc or not parsed.netloc.endswith(_PLATFORM_DOMAIN_SUFFIX):
        return Response(status_code=400, content="Invalid redirect_uri")

    bridge_data = json.dumps({
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
    })
    await redis_client.setex(f"bridge_state:{state}", BRIDGE_STATE_TTL, bridge_data)

    response = RedirectResponse(url=_moneta_login_url(), status_code=302)
    response.set_cookie(
        "mpass_bridge",
        state,
        domain=COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="lax",
        max_age=BRIDGE_STATE_TTL,
        path="/",
    )
    return response


@app.get("/mpass-callback")
async def bridge_callback(request: Request) -> Response:
    if _CLIENTS:
        return await _central_callback(request)
    # Clear bridge cookie on every exit path (success + failure) so a failed
    # callback doesn't leave a stale cookie pointing at consumed Redis state.
    try:
        response = await _bridge_callback_impl(request)
    except Exception:
        logger.exception("bridge_callback: unexpected failure")
        response = Response(status_code=500, content="Internal Server Error")
    return _clear_bridge_cookie(response)


async def _bridge_callback_impl(request: Request) -> Response:
    id_token = request.query_params.get("id_token", "")
    access_token = request.query_params.get("access_token", "") or ""
    refresh_token = request.query_params.get("refresh_token", "") or ""

    if not id_token:
        return Response(status_code=400, content="Missing id_token")

    bridge_key = request.cookies.get("mpass_bridge", "")
    if not bridge_key:
        logger.info("mpass-callback: no bridge cookie — redirecting to portal")
        return _portal_redirect_with_error("expired_flow")

    raw_state = await redis_client.getdel(f"bridge_state:{bridge_key}")
    if not raw_state:
        logger.info("mpass-callback: bridge state missing/expired — redirecting to portal")
        return _portal_redirect_with_error("expired_flow")

    try:
        bridge_data = json.loads(raw_state)
    except json.JSONDecodeError:
        return Response(status_code=500, content="Corrupt bridge state")

    try:
        jwks = await _get_jwks()
        header = jwt.get_unverified_header(id_token)
        kid = header.get("kid")
        signing_key = next(
            (k for k in jwks.get("keys", []) if k.get("kid") == kid),
            None,
        )
        if signing_key is None:
            logger.warning("bridge_callback: no JWKS key matching kid=%r", kid)
            return Response(status_code=401, content="Invalid token")
        claims = jwt.decode(
            id_token,
            PyJWK.from_dict(signing_key).key,
            algorithms=["RS256"],
            audience=OIDC_CLIENT_ID,
            issuer=EXPECTED_ISSUER,
            leeway=60,
        )
    except InvalidTokenError as exc:
        logger.warning("bridge_callback: invalid id_token: %s", exc)
        return Response(status_code=401, content="Invalid token")
    except httpx.HTTPError as exc:
        logger.error("bridge_callback: JWKS fetch failed: %s", exc)
        return Response(status_code=502, content="Unable to verify token")

    if not access_token:
        logger.error("bridge_callback: Moneta did not provide access_token")
        return Response(status_code=502, content="Incomplete token response from provider")

    try:
        await _validate_corporate_id(access_token)
    except CorporateIdMismatch as exc:
        logger.warning("bridge_callback: corporate-id check failed: %s", exc)
        return _portal_redirect_with_error("access_denied", reason=exc.reason)

    if not refresh_token:
        logger.warning("bridge_callback: Moneta did not provide refresh_token — session refresh will not work")

    auth_code = str(uuid.uuid4())
    code_data = json.dumps({
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "code_challenge": bridge_data["code_challenge"],
    })
    await redis_client.setex(f"bridge_code:{auth_code}", BRIDGE_CODE_TTL, code_data)

    callback_url = (
        f"{bridge_data['redirect_uri']}"
        f"?{urlencode({'code': auth_code, 'state': bridge_data['state']})}"
    )
    logger.warning("bridge_callback: auth code issued for sub=%s refresh_token=%s",
                claims.get("sub", "?"), "yes" if refresh_token else "no")
    return RedirectResponse(url=callback_url, status_code=302)


@app.post("/token")
async def bridge_token(request: Request) -> Response:
    if _CLIENTS:
        return await _central_token(request)
    form = await request.form()
    grant_type = form.get("grant_type", "")
    logger.warning("bridge_token: grant_type=%s form_keys=%s", grant_type, list(form.keys()))

    if grant_type == "refresh_token":
        return await _handle_refresh_token(str(form.get("refresh_token", "")))

    if grant_type == "authorization_code":
        return await _handle_authorization_code(
            code=str(form.get("code", "")),
            code_verifier=str(form.get("code_verifier", "")),
        )

    return _token_error("unsupported_grant_type", f"Unsupported grant_type: {grant_type}")


def _token_error(error: str, description: str, status_code: int = 400) -> Response:
    """RFC 6749 §5.2 JSON error response so authlib raises OAuthError."""
    return Response(
        content=json.dumps({"error": error, "error_description": description}),
        media_type="application/json",
        status_code=status_code,
    )


async def _handle_authorization_code(code: str, code_verifier: str) -> Response:
    if not code:
        return _token_error("invalid_request", "Missing code")

    # Atomic get-and-delete prevents the same code from being redeemed twice
    # under concurrent requests (TOCTOU race with separate GET + DEL).
    raw = await redis_client.getdel(f"bridge_code:{code}")
    if not raw:
        return _token_error("invalid_grant", "Invalid or expired code")

    try:
        code_data = json.loads(raw)
    except json.JSONDecodeError:
        return _token_error("server_error", "Corrupt code data", 500)

    if not code_verifier:
        logger.warning("bridge_token: empty code_verifier")
        return _token_error("invalid_grant", "Missing code_verifier")
    logger.warning(
        "bridge_token: PKCE check — verifier=%s… challenge=%s…",
        code_verifier[:12], code_data["code_challenge"][:12],
    )
    if not _verify_pkce(code_verifier, code_data["code_challenge"]):
        logger.warning(
            "bridge_token: PKCE verification failed — full verifier=%s challenge=%s",
            code_verifier, code_data["code_challenge"],
        )
        return _token_error("invalid_grant", "PKCE verification failed")

    try:
        issued_id_token = await _issue_id_token(code_data["id_token"])
    except EmailOverlayUnavailable as exc:
        logger.error("bridge_token: email overlay unavailable: %s", exc)
        return _token_error("temporarily_unavailable", "Email overlay unavailable", status_code=503)
    except ValueError:
        return Response(status_code=500, content="Corrupt id_token in code data")

    body: dict = {
        "access_token": code_data["access_token"],
        "id_token": issued_id_token,
        "token_type": "Bearer",
        "expires_in": SESSION_EXPIRES_IN,
    }
    if code_data.get("refresh_token"):
        body["refresh_token"] = code_data["refresh_token"]

    logger.warning("bridge_token: authorization_code exchange succeeded")
    return Response(content=json.dumps(body), media_type="application/json")


async def _handle_refresh_token(refresh_token: str) -> Response:
    if not refresh_token:
        return Response(status_code=400, content="Missing refresh_token")

    payload: dict = {
        "grant_type": "refresh_token",
        "client_id": OIDC_CLIENT_ID,
        "refresh_token": refresh_token,
    }
    if OIDC_CLIENT_SECRET:
        payload["client_secret"] = OIDC_CLIENT_SECRET

    try:
        token_url = await _get_token_endpoint()
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                token_url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except httpx.HTTPError as exc:
        logger.error("bridge_token refresh: IdP request failed: %s", exc)
        return Response(status_code=502, content="Token refresh failed")

    if resp.status_code != 200:
        logger.warning("bridge_token refresh: IdP returned %d: %s", resp.status_code, resp.text)
        return Response(status_code=resp.status_code, content=resp.text)

    try:
        token_body = resp.json()
    except Exception:
        logger.error("bridge_token refresh: invalid JSON from IdP")
        return Response(status_code=502, content="Invalid response from token endpoint")

    required_fields = ("access_token", "id_token")
    missing_fields = [field for field in required_fields if not token_body.get(field)]
    if missing_fields:
        logger.error(
            "bridge_token refresh: incomplete token response from IdP, missing fields: %s",
            ", ".join(missing_fields),
        )
        return Response(status_code=502, content="Incomplete response from token endpoint")

    # Corporate-id gate (from main): reject early before we re-sign anything.
    try:
        await _validate_corporate_id(token_body["access_token"])
    except CorporateIdMismatch as exc:
        logger.warning("bridge_token refresh: corporate-id check failed: %s", exc)
        reason = exc.reason or "access_denied"
        return Response(
            status_code=403,
            content=json.dumps({"error": "access_denied", "reason": reason}),
            media_type="application/json",
        )

    # Forward Cognito's refresh_token if it issued a new one (rotation enabled);
    # fall back to the original if it didn't (rotation disabled). oauth2-proxy
    # needs *some* refresh_token in the response either way. The previous
    # unconditional echo silently negated refresh-token rotation if it was ever
    # enabled at the Cognito App Client level.
    try:
        issued_id_token = await _issue_id_token(token_body["id_token"])
    except EmailOverlayUnavailable as exc:
        logger.error("bridge_token refresh: email overlay unavailable: %s", exc)
        return _token_error("temporarily_unavailable", "Email overlay unavailable", status_code=503)
    except ValueError:
        return Response(status_code=502, content="Corrupt id_token from IdP")

    body: dict = {
        "access_token": token_body["access_token"],
        "id_token": issued_id_token,
        "token_type": "Bearer",
        "expires_in": SESSION_EXPIRES_IN,
        "refresh_token": token_body.get("refresh_token") or refresh_token,
    }
    logger.info("bridge_token refresh: issued new tokens from IdP")
    return Response(content=json.dumps(body), media_type="application/json")


# ---------------------------------------------------------------------------
# Central mode routes (FOSS-609). Reached only when _CLIENTS is non-empty.
#
# Flow state is keyed by an id this service generates (never the caller's
# state), and carried in a host-only __Host- cookie. The one-time code is bound
# to client_id, redirect_uri and the PKCE challenge, and holds only the claims
# to sign: no Cognito token is stored, so none can be handed to a client.
# Refresh is not offered here (FOSS-611).
# ---------------------------------------------------------------------------

FLOW_COOKIE = "__Host-mpass_flow"
LOGOUT_COOKIE = "__Host-mpass_logout"
CENTRAL_TOKEN_TTL: int = 3600
# Stopgap against a login swap (the IdP leg carries no state, so a captured
# /mpass-callback URL could complete someone else's flow): Cognito tokens must be
# minted after the flow began, allowing this much clock skew. It narrows the
# window to tokens minted while the victim's flow is open; the real fix needs
# the hosted login to round-trip state or a nonce (FOSS-616).
FLOW_TOKEN_SKEW: int = 60
# state and nonce are echoed back and stored in Redis; bound what a caller can park there.
MAX_PARAM_LEN: int = 512
_PKCE_S256_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
_PKCE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
_COPIED_ID_CLAIMS = ("sub", "email", "cognito:username")
_COPIED_CORPORATE_CLAIMS = ("custom:is_corporate", "custom:corporate_id")


def _set_host_cookie(response: Response, key: str, value: str, max_age: int) -> None:
    response.set_cookie(key, value, max_age=max_age, path="/", secure=True, httponly=True, samesite="lax")


def _clear_host_cookie(response: Response, key: str) -> Response:
    response.delete_cookie(key, path="/", secure=True, httponly=True, samesite="lax")
    return response


def _refuse(outcome: str, client_id: str, status_code: int = 400, message: str = "") -> Response:
    """A refusal that redirects nowhere: the request is not trusted enough to
    pick a destination."""
    logger.info("central: refused outcome=%s client_id=%r", outcome, client_id)
    return Response(status_code=status_code, content=message or f"Sign-in refused: {outcome}")


async def _verify_idp_jwt(token: str, **decode_kw) -> dict:
    """Verify a Cognito-issued JWT against the IdP's JWKS. Raises
    InvalidTokenError (an unknown kid included) or httpx.HTTPError."""
    jwks = await _get_jwks()
    kid = jwt.get_unverified_header(token).get("kid")
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if key is None:
        raise InvalidTokenError(f"no JWKS key for kid={kid!r}")
    return jwt.decode(
        token, PyJWK.from_dict(key).key, algorithms=["RS256"],
        issuer=EXPECTED_ISSUER, leeway=60, **decode_kw,
    )


def _sign(claims: dict, typ: str = "JWT") -> str:
    # typ separates our two tokens (RFC 9068: access tokens are at+jwt), so a
    # verifier can refuse an access token presented as an id_token.
    return jwt.encode(claims, _SIGNING_PRIVATE_KEY, algorithm="RS256", headers={"kid": _SIGNING_KID, "typ": typ})


def _minted_during_flow(claims: dict, created_at: int) -> bool:
    iat = claims.get("iat")
    return type(iat) is int and iat >= created_at - FLOW_TOKEN_SKEW


async def _central_authorize(request: Request) -> Response:
    q = request.query_params
    client_id = q.get("client_id", "")
    redirect_uri = q.get("redirect_uri", "")
    client = _CLIENTS.get(client_id)
    if client is None:
        return _refuse("unknown_client", client_id)
    if not _strict_redirect_uri_ok(redirect_uri) or redirect_uri not in client["redirect_uris"]:
        return _refuse("redirect_refused", client_id)
    # An absent method means "plain" (RFC 7636 §4.3), which is refused.
    if q.get("code_challenge_method") != "S256" or not _PKCE_S256_CHALLENGE.fullmatch(q.get("code_challenge", "")):
        return _refuse("pkce_required", client_id)
    if not q.get("state"):
        return _refuse("state_required", client_id)
    if len(q["state"]) > MAX_PARAM_LEN or len(q.get("nonce", "")) > MAX_PARAM_LEN:
        return _refuse("param_too_long", client_id)

    flow_id = secrets.token_urlsafe(32)
    await redis_client.setex(f"central_flow:{flow_id}", BRIDGE_STATE_TTL, json.dumps({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": q["state"],
        "code_challenge": q["code_challenge"],
        "nonce": q.get("nonce", ""),
        "created_at": int(time.time()),
    }))
    logger.info("central: authorize client_id=%r", client_id)
    response = RedirectResponse(url=_moneta_login_url(), status_code=302)
    _set_host_cookie(response, FLOW_COOKIE, flow_id, BRIDGE_STATE_TTL)
    return response


async def _central_callback(request: Request) -> Response:
    try:
        response = await _central_callback_impl(request)
    except Exception:
        logger.exception("central: callback failed unexpectedly")
        response = Response(status_code=500, content="Internal Server Error")
    return _clear_host_cookie(response, FLOW_COOKIE)


async def _central_callback_impl(request: Request) -> Response:
    flow_id = request.cookies.get(FLOW_COOKIE, "")
    raw = await redis_client.getdel(f"central_flow:{flow_id}") if flow_id else None
    if not raw:
        return _refuse("expired_flow", "", message=(
            "This sign-in has expired or was already used. "
            "Go back to the site and sign in again."
        ))
    flow = json.loads(raw)
    client_id = flow["client_id"]
    client = _CLIENTS.get(client_id)
    if client is None or flow["redirect_uri"] not in client["redirect_uris"]:
        return _refuse("unknown_client", client_id)  # deregistered mid-flow (a config reload; Fleet later)

    id_token = request.query_params.get("id_token", "")
    access_token = request.query_params.get("access_token", "")
    if not id_token:
        return _refuse("invalid_token", client_id, 401)
    if not access_token:
        return _refuse("incomplete_idp_response", client_id, 502)
    try:
        id_claims = await _verify_idp_jwt(id_token, audience=OIDC_CLIENT_ID)
        access = await _verify_idp_jwt(access_token, options={"verify_aud": False})
    except InvalidTokenError as exc:
        logger.warning("central: callback token rejected: %s", exc)
        return _refuse("invalid_token", client_id, 401)
    except httpx.HTTPError as exc:
        logger.error("central: IdP JWKS fetch failed: %s", exc)
        return _refuse("idp_unavailable", client_id, 502)
    # Both tokens must be this pool's, for our Cognito client, for one user:
    # the corporate claims come from the access token and are copied onwards.
    if (
        access.get("client_id") != OIDC_CLIENT_ID
        or access.get("token_use") != "access"
        or not id_claims.get("sub")
        or access.get("sub") != id_claims.get("sub")
    ):
        return _refuse("invalid_token", client_id, 401)
    if not (_minted_during_flow(id_claims, flow["created_at"]) and _minted_during_flow(access, flow["created_at"])):
        return _refuse("tokens_predate_flow", client_id, 401)

    binding = client["smb_binding"]
    reason = ""
    if binding is not None:
        if access.get("custom:is_corporate") != "true":
            reason = "not_corporate"
        elif access.get("custom:corporate_id") != binding:
            reason = "wrong_organization"
    sep = "&" if "?" in flow["redirect_uri"] else "?"
    if reason:
        # RFC 6749 §4.1.2.1: the redirect_uri is registered and the flow is
        # ours, so the client hears the refusal and shows its own message.
        logger.info("central: refused outcome=access_denied reason=%s client_id=%r sub=%s",
                    reason, client_id, id_claims["sub"])
        params = {"error": "access_denied", "error_description": reason, "state": flow["state"]}
        return RedirectResponse(url=f"{flow['redirect_uri']}{sep}{urlencode(params)}", status_code=302)

    claims = {k: id_claims[k] for k in _COPIED_ID_CLAIMS if k in id_claims}
    claims.update({k: access[k] for k in _COPIED_CORPORATE_CLAIMS if k in access})
    code = secrets.token_urlsafe(32)
    await redis_client.setex(f"central_code:{code}", BRIDGE_CODE_TTL, json.dumps({
        "client_id": client_id,
        "redirect_uri": flow["redirect_uri"],
        "code_challenge": flow["code_challenge"],
        "nonce": flow["nonce"],
        "claims": claims,
    }))
    logger.info("central: code issued client_id=%r sub=%s", client_id, id_claims["sub"])
    params = {"code": code, "state": flow["state"]}
    return RedirectResponse(url=f"{flow['redirect_uri']}{sep}{urlencode(params)}", status_code=302)


def _authenticate_client(request: Request, form) -> str | Response:
    """client_secret_basic or client_secret_post, never both. Returns the
    authenticated client_id, or the error response."""
    header = request.headers.get("authorization", "")
    if header:
        if "client_secret" in form:
            return _token_error("invalid_request", "Use one client authentication method")
        scheme, _, b64 = header.partition(" ")
        try:
            if scheme.lower() != "basic":
                raise ValueError(scheme)
            raw_id, sep, raw_secret = base64.b64decode(b64, validate=True).decode().partition(":")
            if not sep:
                raise ValueError("no colon")
        except ValueError:  # binascii.Error and UnicodeDecodeError included
            raw_id = raw_secret = ""
        # RFC 6749 §2.3.1: both halves are form-urlencoded before base64.
        client_id, secret = unquote_plus(raw_id), unquote_plus(raw_secret)
        if form.get("client_id", client_id) != client_id:
            client_id = ""
    else:
        client_id = str(form.get("client_id", ""))
        secret = str(form.get("client_secret", ""))

    client = _CLIENTS.get(client_id)
    digest = hashlib.sha256(secret.encode()).hexdigest()
    if client is None or not secret or not any(
        hmac.compare_digest(digest, h) for h in client["secret_sha256"]
    ):
        logger.info("central: refused outcome=invalid_client client_id=%r", client_id)
        response = _token_error("invalid_client", "Client authentication failed", 401)
        response.headers["WWW-Authenticate"] = 'Basic realm="mpass-auth-proxy"'
        return response
    return client_id


async def _central_token(request: Request) -> Response:
    form = await request.form()
    client_id = _authenticate_client(request, form)
    if isinstance(client_id, Response):
        return client_id
    if form.get("grant_type") != "authorization_code":
        return _token_error("unsupported_grant_type", "Only authorization_code is supported")

    code = str(form.get("code", ""))
    # getdel before any check: a failed redemption burns the code.
    raw = await redis_client.getdel(f"central_code:{code}") if code else None
    if not raw:
        return _token_error("invalid_grant", "Invalid or expired code")
    data = json.loads(raw)
    verifier = str(form.get("code_verifier", ""))
    if data["client_id"] != client_id:
        failure = "client_mismatch"
    elif form.get("redirect_uri") != data["redirect_uri"]:
        failure = "redirect_uri_mismatch"
    elif not _PKCE_VERIFIER.fullmatch(verifier) or not _verify_pkce(verifier, data["code_challenge"]):
        failure = "pkce_failed"
    else:
        failure = ""
    if failure:
        logger.info("central: refused outcome=%s client_id=%r", failure, client_id)
        return _token_error("invalid_grant", "Code was not issued for this request")

    now = int(time.time())
    base = {**data["claims"], "iss": MPASS_PROXY_ISSUER_URL, "aud": client_id,
            "iat": now, "exp": now + CENTRAL_TOKEN_TTL}
    id_claims = {**base, "token_use": "id"}
    if data["nonce"]:
        id_claims["nonce"] = data["nonce"]
    body = {
        "access_token": _sign({**base, "token_use": "access"}, typ="at+jwt"),
        "id_token": _sign(id_claims),
        "token_type": "Bearer",
        "expires_in": CENTRAL_TOKEN_TTL,
    }
    logger.info("central: token issued client_id=%r sub=%s", client_id, data["claims"].get("sub"))
    return Response(content=json.dumps(body), media_type="application/json")


@app.get("/.well-known/openid-configuration")
async def openid_configuration() -> dict:
    if not _CLIENTS:
        raise HTTPException(status_code=404)
    iss = MPASS_PROXY_ISSUER_URL
    return {
        "issuer": iss,
        "authorization_endpoint": f"{iss}/authorize",
        "token_endpoint": f"{iss}/token",
        "jwks_uri": f"{iss}/.well-known/jwks.json",
        "end_session_endpoint": f"{iss}/logout",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }


@app.get("/logout")
async def central_logout(request: Request) -> Response:
    if not _CLIENTS:
        raise HTTPException(status_code=404)
    client_id = request.query_params.get("client_id", "")
    target = request.query_params.get("post_logout_redirect_uri", "")
    client = _CLIENTS.get(client_id)
    if client is None:
        return _refuse("unknown_client", client_id)
    if not _strict_redirect_uri_ok(target) or target not in client["post_logout_redirect_uris"]:
        return _refuse("redirect_refused", client_id)
    # Cognito returns to one registered logout_uri (/signed-out); the cookie
    # carries the destination there, and /signed-out checks it again.
    params = {"client_id": OIDC_CLIENT_ID, "logout_uri": f"{MPASS_PROXY_ISSUER_URL}/signed-out"}
    sep = "&" if "?" in OIDC_LOGOUT_URI else "?"
    response = RedirectResponse(url=f"{OIDC_LOGOUT_URI}{sep}{urlencode(params)}", status_code=302)
    value = base64.urlsafe_b64encode(json.dumps({"client_id": client_id, "uri": target}).encode()).decode()
    _set_host_cookie(response, LOGOUT_COOKIE, value, BRIDGE_STATE_TTL)
    logger.info("central: logout client_id=%r", client_id)
    return response


@app.get("/signed-out")
async def central_signed_out(request: Request) -> Response:
    if not _CLIENTS:
        raise HTTPException(status_code=404)
    try:
        dest = json.loads(base64.urlsafe_b64decode(request.cookies.get(LOGOUT_COOKIE, "")))
        client_id, target = dest["client_id"], dest["uri"]
    except (ValueError, TypeError, KeyError):
        client_id = target = ""
    client = _CLIENTS.get(client_id) if isinstance(client_id, str) else None
    if client is not None and isinstance(target, str) and target in client["post_logout_redirect_uris"]:
        response = RedirectResponse(url=target, status_code=302)
    else:
        response = Response(content="<p>You are signed out.</p>", media_type="text/html")
    return _clear_host_cookie(response, LOGOUT_COOKIE)
