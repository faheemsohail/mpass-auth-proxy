"""Central mode (FOSS-609, FOSS-611): one OIDC provider for many registered
clients. Opt-in; main.py dispatches here only when central mode is on, and the
per-bundle routes there are untouched. See README "Central mode".

Shared state (the Redis client, the IdP settings, the signing key, the client
registry) stays in main and is read through `m.` at call time, so a test that
patches main patches what this module sees.
"""
import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from pathlib import Path
from urllib.parse import unquote, unquote_plus, urlencode, urlsplit

import httpx
import jwt
from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse, Response
from jwt import PyJWK
from jwt.exceptions import InvalidTokenError
from starlette.requests import Request

logger = logging.getLogger("main")
router = APIRouter()

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
        if _FLEET_CLIENT_ID.fullmatch(cid):
            raise bad("client_id has Fleet's fd-<uuid> form and would shadow its registry entry")
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


# ---------------------------------------------------------------------------
# Central mode routes (FOSS-609, FOSS-611). Reached only when _CLIENTS is non-empty.
#
# Flow state is keyed by an id this service generates (never the caller's
# state), and carried in a host-only __Host- cookie. The one-time code is bound
# to client_id, redirect_uri and the PKCE challenge, and holds the claims to
# sign plus the Cognito refresh token. No Cognito token is ever handed to a
# client: refresh goes through an opaque handle (_central_refresh).
# ---------------------------------------------------------------------------

FLOW_COOKIE = "__Host-mpass_flow"
LOGOUT_COOKIE = "__Host-mpass_logout"
CENTRAL_TOKEN_TTL: int = 3600
# A central session ends this long after sign-in, whatever happens: a refresh
# never extends it (security review of #12, LOW-1; the 12 h absolute rule).
CENTRAL_SESSION_MAX: int = 12 * 3600
# Stopgap against a login swap (the IdP leg carries no state, so a captured
# /mpass-callback URL could complete someone else's flow): Cognito tokens must be
# minted after the flow began, allowing this much clock skew. It narrows the
# window to tokens minted from FLOW_TOKEN_SKEW before the flow opens until it
# closes (up to BRIDGE_STATE_TTL); the real fix needs
# the hosted login to round-trip state or a nonce (FOSS-616).
FLOW_TOKEN_SKEW: int = 60
# state and nonce are echoed back and stored in Redis; bound what a caller can park there.
MAX_PARAM_LEN: int = 512
_PKCE_S256_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
_PKCE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
_COPIED_ID_CLAIMS = ("sub", "email", "cognito:username")
_COPIED_CORPORATE_CLAIMS = ("custom:is_corporate", "custom:corporate_id")


# ---------------------------------------------------------------------------
# Fleet's registry (FOSS-611, Plan 3 §4). Static clients are looked up first;
# only `fd-` ids go to Fleet. Three answers, kept apart:
#   an entry   -- "yes", cached REGISTRY_TTL s;
#   None       -- "no" (404, or an id Fleet cannot hold), never cached;
#   RegistryUnavailable -- "we could not ask" (unreachable, non-200/404, or a
#                 reply off the §4.1 shape). The last real "yes" is served for
#                 up to REGISTRY_STALE_MAX s, then 503. Never a 400.
# One attempt per request, bounded by REGISTRY_TIMEOUT: the browser's or
# oauth2-proxy's own retry is the retry, so an outage costs Fleet no more load.
# ---------------------------------------------------------------------------

REGISTRY_TTL: int = 30
REGISTRY_STALE_MAX: int = 600
REGISTRY_TIMEOUT: float = 3.0
# Fleet's own client_id pattern (contracts/FOSS-611.openapi.yaml); any other id is
# unknown, so it is never sent.
_FLEET_CLIENT_ID = re.compile(r"fd-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# A lowercase DNS name of two or more labels: nothing that can carry a port,
# userinfo, path, `\` or `%` into the redirect URI built from it.
_HOSTNAME = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_registry_cache: dict[str, tuple[float, dict]] = {}  # client_id -> (answered_at, entry)


class RegistryUnavailable(Exception):
    """Fleet could not be asked. Not "no": callers answer 503, never 400."""


def _fleet_entry(client_id: str, doc) -> dict:
    """Map a 200 reply (AuthClientOut, foss-fleet-provisioning
    contracts/FOSS-611.openapi.yaml at 9fc7f75; a copy is in tests/contracts/)
    onto the static-client shape. Anything off that schema raises ValueError,
    which the caller treats as "could not ask": lenient parsing would hide drift.
    A base_domain that is a string but not a plain DNS name is in the schema; it
    yields no redirect URI, so /authorize refuses it."""
    if not isinstance(doc, dict) or doc.get("client_id") != client_id:
        raise ValueError("client_id")
    for key in ("deployment_id", "smb_id", "base_domain"):
        if not isinstance(doc.get(key), str):
            raise ValueError(key)
    hashes = doc.get("secret_sha256")
    if not isinstance(hashes, list) or not 1 <= len(hashes) <= 2 or not all(
        isinstance(h, str) and _SHA256_HEX.fullmatch(h) for h in hashes
    ):
        raise ValueError("secret_sha256")
    scheme, state, base = doc.get("scheme"), doc.get("state"), doc["base_domain"]
    if scheme not in ("https", "http"):
        raise ValueError("scheme")
    if state not in ("active", "suspended"):
        raise ValueError("state")
    ok = _HOSTNAME.fullmatch(base) is not None
    return {
        "client_id": client_id,
        "secret_sha256": hashes,
        # Fleet's OAUTH2_PROXY_REDIRECT_URL, and the sign-in host's root.
        "redirect_uris": [f"{scheme}://auth.{base}/oauth2/callback"] if ok else [],
        "post_logout_redirect_uris": [f"{scheme}://auth.{base}/"] if ok else [],
        # "" fails closed at /mpass-callback: see _corporate_refusal.
        "smb_binding": doc["smb_id"],
        "state": state,
        "fleet": True,
    }


async def _fetch_registry(client_id: str) -> dict | None:
    url = f"{m.FLEET_REGISTRY_URL}/internal/auth/clients/{client_id}"
    try:
        async with httpx.AsyncClient(timeout=REGISTRY_TIMEOUT) as http:
            r = await http.get(url, headers={"Authorization": f"Bearer {m.FLEET_BROKER_TOKEN}"})
    except httpx.HTTPError as exc:
        raise RegistryUnavailable(type(exc).__name__) from None
    if r.status_code == 404:
        # Only the contract's 404 is "no". Any other 404 (a wrong FLEET_REGISTRY_URL,
        # a proxy in the way) is a misconfiguration, not an answer about the client.
        try:
            reason = r.json().get("error")
        except (ValueError, AttributeError):
            reason = None
        if reason not in ("unknown_client", "no_base_domain"):
            raise RegistryUnavailable("HTTP 404 off the contract")
        logger.info("central: registry says no client_id=%r reason=%s", client_id, reason)
        return None
    if r.status_code != 200:
        raise RegistryUnavailable(f"HTTP {r.status_code}")
    try:
        return _fleet_entry(client_id, r.json())
    except ValueError as exc:  # JSONDecodeError included
        raise RegistryUnavailable(f"malformed reply ({exc})") from None


async def _lookup(client_id: str) -> dict | None:
    """The client's entry, None for "no such client", or RegistryUnavailable."""
    static = m._CLIENTS.get(client_id)
    if static is not None or not m.FLEET_REGISTRY_URL or not _FLEET_CLIENT_ID.fullmatch(client_id):
        return static
    now = time.time()
    hit = _registry_cache.get(client_id)
    if hit and now - hit[0] < REGISTRY_TTL:
        return hit[1]
    try:
        found = await _fetch_registry(client_id)
    except RegistryUnavailable as exc:
        stale = hit is not None and now - hit[0] < REGISTRY_STALE_MAX
        logger.warning("broker.registry_unavailable client_id=%r cause=%s serving_stale=%s",
                       client_id, exc, stale)
        if stale:
            return hit[1]  # served, never re-stamped: the clock runs from Fleet's last answer
        raise
    if found is None:
        _registry_cache.pop(client_id, None)
    else:
        _registry_cache[client_id] = (now, found)
    return found


def _unavailable(client_id: str) -> Response:
    return _refuse("registry_unavailable", client_id, 503,
                   "Sign-in is temporarily unavailable. Try again in a few minutes.")


def _inactive(client: dict) -> bool:
    return client.get("fleet", False) and client["state"] != "active"


def _corporate_refusal(client: dict, access: dict) -> str:
    """"" to admit, else the access_denied reason. Equality is verbatim, and a
    Fleet entry with no SMB admits no one: a missing binding must never match
    a missing claim."""
    binding = client["smb_binding"]
    if client.get("fleet") and not binding:
        return "no_smb_binding"
    if binding is None:
        return ""  # a static client with no binding (the portal checks the claims itself)
    if access.get("custom:is_corporate") != "true":
        return "not_corporate"
    if access.get("custom:corporate_id") != binding:
        return "wrong_organization"
    return ""


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
    jwks = await m._get_jwks()
    kid = jwt.get_unverified_header(token).get("kid")
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if key is None:
        raise InvalidTokenError(f"no JWKS key for kid={kid!r}")
    return jwt.decode(
        token, PyJWK.from_dict(key).key, algorithms=["RS256"],
        issuer=m.EXPECTED_ISSUER, leeway=60, **decode_kw,
    )


def _sign(claims: dict, typ: str = "JWT") -> str:
    # typ separates our two tokens (RFC 9068: access tokens are at+jwt), so a
    # verifier can refuse an access token presented as an id_token.
    return jwt.encode(claims, m._SIGNING_PRIVATE_KEY, algorithm="RS256", headers={"kid": m._SIGNING_KID, "typ": typ})


def _idp_pair_ok(id_claims: dict, access: dict) -> bool:
    """Both tokens are this pool's, for our Cognito client, for one user: the
    corporate claims come from the access token and are copied onwards."""
    return (
        access.get("client_id") == m.OIDC_CLIENT_ID
        and access.get("token_use") == "access"
        and bool(id_claims.get("sub"))
        and access.get("sub") == id_claims.get("sub")
    )


def _claims_to_sign(id_claims: dict, access: dict) -> dict:
    claims = {k: id_claims[k] for k in _COPIED_ID_CLAIMS if k in id_claims}
    claims.update({k: access[k] for k in _COPIED_CORPORATE_CLAIMS if k in access})
    return claims


def _sid(handle: str) -> str:
    """The session id: the refresh handle's sha256. Redis keys sessions by it, so
    Redis never holds a presentable handle, and tokens carry it as `sid` so
    /logout can end the session from an id_token_hint."""
    return hashlib.sha256(handle.encode()).hexdigest()


def _token_body(client_id: str, claims: dict, nonce: str = "", refresh_handle: str = "") -> Response:
    now = int(time.time())
    base = {**claims, "iss": m.MPASS_PROXY_ISSUER_URL, "aud": client_id,
            "iat": now, "exp": now + CENTRAL_TOKEN_TTL}
    if refresh_handle:
        base["sid"] = _sid(refresh_handle)
    id_claims = {**base, "token_use": "id"}
    if nonce:
        id_claims["nonce"] = nonce
    body = {
        "access_token": _sign({**base, "token_use": "access"}, typ="at+jwt"),
        "id_token": _sign(id_claims),
        "token_type": "Bearer",
        "expires_in": CENTRAL_TOKEN_TTL,
    }
    if refresh_handle:
        body["refresh_token"] = refresh_handle
    return Response(content=json.dumps(body), media_type="application/json")


def _minted_during_flow(claims: dict, created_at: int) -> bool:
    iat = claims.get("iat")
    return type(iat) is int and iat >= created_at - FLOW_TOKEN_SKEW


async def _central_authorize(request: Request) -> Response:
    q = request.query_params
    client_id = q.get("client_id", "")
    redirect_uri = q.get("redirect_uri", "")
    try:
        client = await _lookup(client_id)
    except RegistryUnavailable:
        return _unavailable(client_id)
    if client is None:
        return _refuse("unknown_client", client_id)
    if _inactive(client):
        return _refuse("client_inactive", client_id)
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
    await m.redis_client.setex(f"central_flow:{flow_id}", m.BRIDGE_STATE_TTL, json.dumps({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "smb_id": client["smb_binding"],
        "state": q["state"],
        "code_challenge": q["code_challenge"],
        "nonce": q.get("nonce", ""),
        "created_at": int(time.time()),
    }))
    logger.info("central: authorize client_id=%r", client_id)
    response = RedirectResponse(url=m._moneta_login_url(), status_code=302)
    _set_host_cookie(response, FLOW_COOKIE, flow_id, m.BRIDGE_STATE_TTL)
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
    raw = await m.redis_client.getdel(f"central_flow:{flow_id}") if flow_id else None
    if not raw:
        return _refuse("expired_flow", "", message=(
            "This sign-in has expired or was already used. "
            "Go back to the site and sign in again."
        ))
    flow = json.loads(raw)
    client_id = flow["client_id"]
    try:
        client = await _lookup(client_id)
    except RegistryUnavailable:
        return _unavailable(client_id)
    # Deregistered or suspended mid-flow (a CLIENTS_FILE restart, or Fleet). The
    # binding below is checked against this fresh entry, not the flow's copy.
    if (
        client is None
        or _inactive(client)
        or flow["redirect_uri"] not in client["redirect_uris"]
    ):
        return _refuse("unknown_client", client_id)

    id_token = request.query_params.get("id_token", "")
    access_token = request.query_params.get("access_token", "")
    if not id_token:
        return _refuse("invalid_token", client_id, 401)
    if not access_token:
        return _refuse("incomplete_idp_response", client_id, 502)
    try:
        id_claims = await _verify_idp_jwt(id_token, audience=m.OIDC_CLIENT_ID)
        access = await _verify_idp_jwt(access_token, options={"verify_aud": False})
    except InvalidTokenError as exc:
        logger.warning("central: callback token rejected: %s", exc)
        return _refuse("invalid_token", client_id, 401)
    except httpx.HTTPError as exc:
        logger.error("central: IdP JWKS fetch failed: %s", exc)
        return _refuse("idp_unavailable", client_id, 502)
    if not _idp_pair_ok(id_claims, access):
        return _refuse("invalid_token", client_id, 401)
    if not (_minted_during_flow(id_claims, flow["created_at"]) and _minted_during_flow(access, flow["created_at"])):
        return _refuse("tokens_predate_flow", client_id, 401)

    reason = _corporate_refusal(client, access)
    sep = "&" if "?" in flow["redirect_uri"] else "?"
    if reason:
        # RFC 6749 §4.1.2.1: the redirect_uri is registered and the flow is
        # ours, so the client hears the refusal and shows its own message.
        logger.info("central: refused outcome=access_denied reason=%s client_id=%r sub=%s",
                    reason, client_id, id_claims["sub"])
        params = {"error": "access_denied", "error_description": reason, "state": flow["state"]}
        return RedirectResponse(url=f"{flow['redirect_uri']}{sep}{urlencode(params)}", status_code=302)

    claims = _claims_to_sign(id_claims, access)
    code = secrets.token_urlsafe(32)
    await m.redis_client.setex(f"central_code:{code}", m.BRIDGE_CODE_TTL, json.dumps({
        "client_id": client_id,
        "redirect_uri": flow["redirect_uri"],
        "code_challenge": flow["code_challenge"],
        "nonce": flow["nonce"],
        "claims": claims,
        # Kept server-side only: /token hands the client an opaque handle to it.
        "idp_refresh_token": request.query_params.get("refresh_token", ""),
    }))
    logger.info("central: code issued client_id=%r sub=%s", client_id, id_claims["sub"])
    params = {"code": code, "state": flow["state"]}
    return RedirectResponse(url=f"{flow['redirect_uri']}{sep}{urlencode(params)}", status_code=302)


async def _authenticate_client(request: Request, form) -> dict | Response:
    """client_secret_basic or client_secret_post, never both. Returns the
    authenticated, active client's entry, or the error response."""
    header = request.headers.get("authorization", "")
    if header:
        if "client_secret" in form:
            return m._token_error("invalid_request", "Use one client authentication method")
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

    try:
        client = await _lookup(client_id)
    except RegistryUnavailable:
        return m._token_error("temporarily_unavailable", "Client registry unavailable", 503)
    digest = hashlib.sha256(secret.encode()).hexdigest()
    if client is None or not secret or not any(
        hmac.compare_digest(digest, h) for h in client["secret_sha256"]
    ):
        logger.info("central: refused outcome=invalid_client client_id=%r", client_id)
        response = m._token_error("invalid_client", "Client authentication failed", 401)
        response.headers["WWW-Authenticate"] = 'Basic realm="mpass-auth-proxy"'
        return response
    if _inactive(client):
        logger.info("central: refused outcome=client_inactive client_id=%r", client_id)
        return m._token_error("unauthorized_client", "Client is not active")
    return client


async def _central_token(request: Request) -> Response:
    form = await request.form()
    client = await _authenticate_client(request, form)
    if isinstance(client, Response):
        return client
    client_id = client["client_id"]
    if form.get("grant_type") == "refresh_token":
        return await _central_refresh(client, str(form.get("refresh_token", "")))
    if form.get("grant_type") != "authorization_code":
        return m._token_error("unsupported_grant_type", "Only authorization_code and refresh_token are supported")

    code = str(form.get("code", ""))
    # getdel before any check: a failed redemption burns the code.
    raw = await m.redis_client.getdel(f"central_code:{code}") if code else None
    if not raw:
        return m._token_error("invalid_grant", "Invalid or expired code")
    data = json.loads(raw)
    verifier = str(form.get("code_verifier", ""))
    if data["client_id"] != client_id:
        failure = "client_mismatch"
    elif form.get("redirect_uri") != data["redirect_uri"]:
        failure = "redirect_uri_mismatch"
    elif not _PKCE_VERIFIER.fullmatch(verifier) or not m._verify_pkce(verifier, data["code_challenge"]):
        failure = "pkce_failed"
    else:
        failure = ""
    if failure:
        logger.info("central: refused outcome=%s client_id=%r", failure, client_id)
        return m._token_error("invalid_grant", "Code was not issued for this request")

    handle = ""
    if data.get("idp_refresh_token"):
        handle = secrets.token_urlsafe(32)
        await m.redis_client.setex(f"central_refresh:{_sid(handle)}", CENTRAL_SESSION_MAX, json.dumps({
            "client_id": client_id, "sub": data["claims"].get("sub"),
            "idp_refresh_token": data["idp_refresh_token"],
            "expires_at": int(time.time()) + CENTRAL_SESSION_MAX,
        }))
    logger.info("central: token issued client_id=%r sub=%s", client_id, data["claims"].get("sub"))
    return _token_body(client_id, data["claims"], data["nonce"], handle)


def _oauth_error(resp: httpx.Response) -> str:
    try:
        return str(resp.json().get("error", ""))
    except (ValueError, AttributeError):
        return ""


async def _central_refresh(client: dict, handle: str) -> Response:
    """refresh_token grant. The handle is ours and bound to one client; the
    Cognito refresh token behind it never leaves this service. Not rotated, so
    a second delivery of the same refresh succeeds (oauth2-proxy can refresh
    concurrently). The client's state was checked by _authenticate_client; the
    corporate binding is checked here against the fresh Cognito tokens.

    A refusal that is an answer (unknown handle, the IdP says no, the binding
    fails) burns the handle; "we could not ask" (IdP unreachable) keeps it."""
    client_id = client["client_id"]
    key = f"central_refresh:{_sid(handle)}"
    raw = await m.redis_client.get(key) if handle else None
    rec = json.loads(raw) if raw else None
    if rec is None or rec["client_id"] != client_id:
        logger.info("central: refused outcome=refresh_unknown client_id=%r", client_id)
        return m._token_error("invalid_grant", "Invalid or expired refresh token")
    if rec["expires_at"] <= int(time.time()):  # Redis's TTL should have got here first
        await m.redis_client.delete(key)
        logger.info("central: refused outcome=session_expired client_id=%r sub=%s", client_id, rec["sub"])
        return m._token_error("invalid_grant", "Session expired; sign in again")

    payload = {"grant_type": "refresh_token", "client_id": m.OIDC_CLIENT_ID,
               "refresh_token": rec["idp_refresh_token"]}
    if m.OIDC_CLIENT_SECRET:
        payload["client_secret"] = m.OIDC_CLIENT_SECRET
    try:
        token_url = await m._get_token_endpoint()
        async with httpx.AsyncClient(timeout=10.0) as http:
            resp = await http.post(token_url, data=payload)
        # Only invalid_grant is about the user's token. invalid_client and the
        # rest are about us (a wrong central secret): burning on those would
        # end every session over a misconfiguration.
        if resp.status_code == 400 and _oauth_error(resp) == "invalid_grant":
            await m.redis_client.delete(key)
            logger.info("central: refused outcome=refresh_idp_refused client_id=%r sub=%s", client_id, rec["sub"])
            return m._token_error("invalid_grant", "Refresh token no longer valid")
        resp.raise_for_status()
        tokens = resp.json()
        id_claims = await _verify_idp_jwt(str(tokens.get("id_token", "")), audience=m.OIDC_CLIENT_ID)
        access = await _verify_idp_jwt(str(tokens.get("access_token", "")), options={"verify_aud": False})
    except (httpx.HTTPError, ValueError) as exc:  # unreachable, 5xx, or a reply we cannot read
        logger.error("central: refresh IdP unavailable client_id=%r: %s", client_id, type(exc).__name__)
        return m._token_error("temporarily_unavailable", "Identity provider unavailable", 503)
    except InvalidTokenError:
        logger.error("central: refresh IdP returned an invalid token client_id=%r", client_id)
        return m._token_error("temporarily_unavailable", "Identity provider unavailable", 503)
    if not _idp_pair_ok(id_claims, access) or id_claims["sub"] != rec["sub"]:
        await m.redis_client.delete(key)
        logger.warning("central: refused outcome=refresh_wrong_subject client_id=%r sub=%s", client_id, rec["sub"])
        return m._token_error("invalid_grant", "Refresh token no longer valid")

    reason = _corporate_refusal(client, access)
    if reason:
        await m.redis_client.delete(key)
        logger.info("central: refused outcome=access_denied reason=%s client_id=%r sub=%s",
                    reason, client_id, rec["sub"])
        return Response(status_code=403, media_type="application/json",
                        content=json.dumps({"error": "access_denied", "error_description": reason}))

    if tokens.get("refresh_token"):  # Cognito rotation, if it is ever turned on
        rec["idp_refresh_token"] = tokens["refresh_token"]
    # The remaining lifetime only: a refresh never extends the session.
    await m.redis_client.setex(key, max(1, rec["expires_at"] - int(time.time())), json.dumps(rec))
    logger.info("central: token refreshed client_id=%r sub=%s", client_id, rec["sub"])
    return _token_body(client_id, _claims_to_sign(id_claims, access), refresh_handle=handle)


@router.get("/.well-known/openid-configuration")
async def openid_configuration() -> dict:
    if not m._CLIENTS:
        raise HTTPException(status_code=404)
    iss = m.MPASS_PROXY_ISSUER_URL
    return {
        "issuer": iss,
        "authorization_endpoint": f"{iss}/authorize",
        "token_endpoint": f"{iss}/token",
        "jwks_uri": f"{iss}/.well-known/jwks.json",
        "end_session_endpoint": f"{iss}/logout",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }


async def _end_session(client_id: str, hint: str) -> None:
    """Delete the refresh session an id_token_hint names, so a copied session
    cannot refresh after sign-out. The hint must be ours and for this client;
    an expired one still counts (OIDC RP-initiated logout). Anything else is
    ignored: the sign-out itself still proceeds."""
    if not hint:
        return
    try:
        claims = jwt.decode(hint, m._SIGNING_PRIVATE_KEY.public_key(), algorithms=["RS256"],
                            audience=client_id, issuer=m.MPASS_PROXY_ISSUER_URL,
                            options={"verify_exp": False})
    except InvalidTokenError:
        logger.info("central: logout id_token_hint ignored client_id=%r", client_id)
        return
    sid = claims.get("sid")
    if not isinstance(sid, str) or not _SHA256_HEX.fullmatch(sid):
        return
    key = f"central_refresh:{sid}"
    raw = await m.redis_client.get(key)
    if raw and json.loads(raw)["client_id"] == client_id:
        await m.redis_client.delete(key)
        logger.info("central: session ended client_id=%r sub=%s", client_id, claims.get("sub"))


async def _backend_logout(hint: str) -> None:
    """oauth2-proxy's backend logout: a server-side GET carrying only the
    session's id_token. The audience is read unverified only to choose which
    client to verify against; it must name a static or an fd- client, and
    _end_session then verifies the signature, issuer and that audience. No
    registry call: the token is ours, so this works while Fleet is down."""
    try:
        aud = jwt.decode(hint, options={"verify_signature": False}).get("aud") if hint else None
    except InvalidTokenError:
        aud = None
    if isinstance(aud, str) and (aud in m._CLIENTS or _FLEET_CLIENT_ID.fullmatch(aud)):
        await _end_session(aud, hint)


@router.get("/logout")
async def central_logout(request: Request) -> Response:
    if not m._CLIENTS:
        raise HTTPException(status_code=404)
    q = request.query_params
    if "client_id" not in q and "post_logout_redirect_uri" not in q:
        # oauth2-proxy's OAUTH2_PROXY_BACKEND_LOGOUT_URL form. Always 204, no
        # redirect: v7.15.5 accepts 200 or 204 and its http.Get would follow a
        # redirect; the same answer for every hint gives no oracle.
        await _backend_logout(q.get("id_token_hint", ""))
        return Response(status_code=204)
    client_id = request.query_params.get("client_id", "")
    target = request.query_params.get("post_logout_redirect_uri", "")
    try:
        client = await _lookup(client_id)
    except RegistryUnavailable:
        return _unavailable(client_id)
    if client is None:
        return _refuse("unknown_client", client_id)
    # Exact match only: clusters whitelist this service's host for oauth2-proxy's
    # sign-out rd, which is safe only while this check is exact (FOSS-607 §3.3).
    # A suspended deployment may still sign out; the target is its own host.
    if not _strict_redirect_uri_ok(target) or target not in client["post_logout_redirect_uris"]:
        return _refuse("redirect_refused", client_id)
    # Cognito returns to one registered logout_uri (/signed-out); the cookie
    # carries the destination there, and /signed-out checks it again.
    await _end_session(client_id, request.query_params.get("id_token_hint", ""))
    params = {"client_id": m.OIDC_CLIENT_ID, "logout_uri": f"{m.MPASS_PROXY_ISSUER_URL}/signed-out"}
    sep = "&" if "?" in m.OIDC_LOGOUT_URI else "?"
    response = RedirectResponse(url=f"{m.OIDC_LOGOUT_URI}{sep}{urlencode(params)}", status_code=302)
    value = base64.urlsafe_b64encode(json.dumps({"client_id": client_id, "uri": target}).encode()).decode()
    _set_host_cookie(response, LOGOUT_COOKIE, value, m.BRIDGE_STATE_TTL)
    logger.info("central: logout client_id=%r", client_id)
    return response


@router.get("/signed-out")
async def central_signed_out(request: Request) -> Response:
    if not m._CLIENTS:
        raise HTTPException(status_code=404)
    try:
        dest = json.loads(base64.urlsafe_b64decode(request.cookies.get(LOGOUT_COOKIE, "")))
        client_id, target = dest["client_id"], dest["uri"]
    except (ValueError, TypeError, KeyError):
        client_id = target = ""
    client = None
    if isinstance(client_id, str):
        try:
            client = await _lookup(client_id)  # re-checked: the cookie is the browser's
        except RegistryUnavailable:
            client = None  # no redirect then, only the page
    if client is not None and isinstance(target, str) and target in client["post_logout_redirect_uris"]:
        response = RedirectResponse(url=target, status_code=302)
    else:
        response = Response(content="<p>You are signed out.</p>", media_type="text/html")
    return _clear_host_cookie(response, LOGOUT_COOKIE)


# Last, so that whichever of main and central is imported first, the other
# finds every name it needs at import time.
import main as m  # noqa: E402
