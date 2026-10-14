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


def _minted_during_flow(claims: dict, created_at: int) -> bool:
    iat = claims.get("iat")
    return type(iat) is int and iat >= created_at - FLOW_TOKEN_SKEW


async def _central_authorize(request: Request) -> Response:
    q = request.query_params
    client_id = q.get("client_id", "")
    redirect_uri = q.get("redirect_uri", "")
    client = m._CLIENTS.get(client_id)
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
    await m.redis_client.setex(f"central_flow:{flow_id}", m.BRIDGE_STATE_TTL, json.dumps({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
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
    client = m._CLIENTS.get(client_id)
    if client is None or flow["redirect_uri"] not in client["redirect_uris"]:
        return _refuse("unknown_client", client_id)  # deregistered mid-flow (a restart with a new CLIENTS_FILE; Fleet later)

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
    # Both tokens must be this pool's, for our Cognito client, for one user:
    # the corporate claims come from the access token and are copied onwards.
    if (
        access.get("client_id") != m.OIDC_CLIENT_ID
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
    await m.redis_client.setex(f"central_code:{code}", m.BRIDGE_CODE_TTL, json.dumps({
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

    client = m._CLIENTS.get(client_id)
    digest = hashlib.sha256(secret.encode()).hexdigest()
    if client is None or not secret or not any(
        hmac.compare_digest(digest, h) for h in client["secret_sha256"]
    ):
        logger.info("central: refused outcome=invalid_client client_id=%r", client_id)
        response = m._token_error("invalid_client", "Client authentication failed", 401)
        response.headers["WWW-Authenticate"] = 'Basic realm="mpass-auth-proxy"'
        return response
    return client_id


async def _central_token(request: Request) -> Response:
    form = await request.form()
    client_id = _authenticate_client(request, form)
    if isinstance(client_id, Response):
        return client_id
    if form.get("grant_type") != "authorization_code":
        return m._token_error("unsupported_grant_type", "Only authorization_code is supported")

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

    now = int(time.time())
    base = {**data["claims"], "iss": m.MPASS_PROXY_ISSUER_URL, "aud": client_id,
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
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }


@router.get("/logout")
async def central_logout(request: Request) -> Response:
    if not m._CLIENTS:
        raise HTTPException(status_code=404)
    client_id = request.query_params.get("client_id", "")
    target = request.query_params.get("post_logout_redirect_uri", "")
    client = m._CLIENTS.get(client_id)
    if client is None:
        return _refuse("unknown_client", client_id)
    if not _strict_redirect_uri_ok(target) or target not in client["post_logout_redirect_uris"]:
        return _refuse("redirect_refused", client_id)
    # Cognito returns to one registered logout_uri (/signed-out); the cookie
    # carries the destination there, and /signed-out checks it again.
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
    client = m._CLIENTS.get(client_id) if isinstance(client_id, str) else None
    if client is not None and isinstance(target, str) and target in client["post_logout_redirect_uris"]:
        response = RedirectResponse(url=target, status_code=302)
    else:
        response = Response(content="<p>You are signed out.</p>", media_type="text/html")
    return _clear_host_cookie(response, LOGOUT_COOKIE)


# Last, so that whichever of main and central is imported first, the other
# finds every name it needs at import time.
import main as m  # noqa: E402
