"""fake-mpass: LOCAL / SANDBOX stand-in for mPass's hosted login + Cognito.

Imitates only what mpass-auth-proxy's main.py calls (see README). Signs with its
own key; never trust that key anywhere real.
"""
import hashlib
import json
import os
import time
import uuid
from html import escape
from pathlib import Path
from urllib.parse import urlencode, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jwt.algorithms import RSAAlgorithm

TOKEN_TTL = 3600
REFRESH_PREFIX = "fake-refresh:"
GUARD_VAR = "FAKE_MPASS_I_KNOW_THIS_IS_NOT_PRODUCTION"


def _load_key(path: str):
    p = Path(path) if path else None
    if p and p.exists():
        if p.stat().st_mode & 0o077:
            raise RuntimeError(f"fake-mpass: key file {p} is group/world readable; chmod 600 it")
        return serialization.load_pem_private_key(p.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if p:
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        # O_EXCL: never follow or clobber an existing path; 0600 from creation.
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    return key


def _redirect_allowed(url: str, allowed: list[str]) -> bool:
    """Exact origin + path prefix match against the allowlist (like Cognito's
    registered URLs). Rejects userinfo and backslashes outright."""
    if "\\" in url:
        return False
    u = urlparse(url)
    if u.scheme not in ("http", "https") or "@" in u.netloc or not u.hostname:
        return False
    for entry in allowed:
        a = urlparse(entry)
        if (a.scheme, a.netloc.lower()) != (u.scheme, u.netloc.lower()):
            continue
        base = a.path.rstrip("/")
        if u.path == base or u.path.startswith(base + "/"):
            return True
    return False


def create_app(
    issuer: str | None = None,
    users_file: str | None = None,
    key_file: str | None = None,
    allowed_redirects: list[str] | None = None,
) -> FastAPI:
    if os.environ.get(GUARD_VAR) != "1":
        raise RuntimeError(
            f"fake-mpass refuses to start: set {GUARD_VAR}=1. It issues tokens for "
            "fixed test users and must never run in production."
        )
    issuer = (issuer or os.environ["FAKE_MPASS_ISSUER_URL"]).rstrip("/")
    users_file = users_file or os.environ.get(
        "FAKE_MPASS_USERS_FILE", str(Path(__file__).with_name("users.json"))
    )
    key = _load_key(key_file if key_file is not None else os.environ.get("FAKE_MPASS_KEY_FILE", ""))
    if allowed_redirects is None:
        allowed_redirects = [
            x.strip() for x in os.environ.get("FAKE_MPASS_ALLOWED_REDIRECTS", "").split(",") if x.strip()
        ]
    users = {u["username"]: u for u in json.loads(Path(users_file).read_text())["users"]}

    kid = hashlib.sha256(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )).hexdigest()[:32]
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid=kid, use="sig", alg="RS256")

    parsed = urlparse(issuer)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    prefix = parsed.path  # e.g. /us-east-1_pool; "" if the issuer is the origin

    def sign(claims: dict) -> str:
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})

    def tokens(username: str, client_id: str) -> dict:
        u = users[username]
        now = int(time.time())
        sub = str(uuid.uuid5(uuid.NAMESPACE_URL, f"fake-mpass/{username}"))
        # Cognito custom attributes are strings: "true"/"false", never booleans.
        custom = {"custom:is_corporate": "true" if u.get("corporate_id") and u.get("is_corporate", True) else "false"}
        if u.get("corporate_id"):
            custom["custom:corporate_id"] = u["corporate_id"]
        base = {"iss": issuer, "sub": sub, "iat": now, "exp": now + TOKEN_TTL, **custom}
        return {
            "id_token": sign({**base, "aud": client_id, "token_use": "id", "cognito:username": username, "email": u["email"]}),
            "access_token": sign({**base, "client_id": client_id, "token_use": "access", "username": username}),
        }

    app = FastAPI(docs_url=None, redoc_url=None)

    @app.get(f"{prefix}/.well-known/openid-configuration")
    def discovery():
        return {
            "issuer": issuer,
            "jwks_uri": f"{issuer}/.well-known/jwks.json",
            "token_endpoint": f"{origin}/oauth2/token",
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    @app.get(f"{prefix}/.well-known/jwks.json")
    def jwks():
        return {"keys": [jwk]}

    @app.get("/users/login", response_class=HTMLResponse)
    def login(client_id: str, client_redirect_url: str):
        rows = "".join(
            f'<li><a href="/users/login/as?{escape(urlencode({"user": n, "client_id": client_id, "client_redirect_url": client_redirect_url}))}">'
            f'{escape(n)}</a> &mdash; {escape(u["email"])} ({escape(u.get("corporate_id") or "individual")})</li>'
            for n, u in users.items()
        )
        return f"<h1>fake-mpass: sign in as&hellip;</h1><p>Local/sandbox only.</p><ul>{rows}</ul>"

    @app.get("/users/login/as")
    def login_as(user: str, client_id: str, client_redirect_url: str):
        if user not in users or not _redirect_allowed(client_redirect_url, allowed_redirects):
            return JSONResponse({"error": "bad request"}, status_code=400)
        t = tokens(user, client_id)
        t["refresh_token"] = REFRESH_PREFIX + user
        sep = "&" if "?" in client_redirect_url else "?"
        return RedirectResponse(f"{client_redirect_url}{sep}{urlencode(t)}", status_code=302)

    @app.post("/oauth2/token")
    def token(grant_type: str = Form(""), refresh_token: str = Form(""), client_id: str = Form("")):
        user = refresh_token.removeprefix(REFRESH_PREFIX)
        if grant_type != "refresh_token":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        if not refresh_token.startswith(REFRESH_PREFIX) or user not in users:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        # Like Cognito: no new refresh_token in a refresh response.
        return {**tokens(user, client_id), "token_type": "Bearer", "expires_in": TOKEN_TTL}

    @app.get("/logout")
    def logout(client_id: str = "", logout_uri: str = ""):
        if not _redirect_allowed(logout_uri, allowed_redirects):
            return HTMLResponse("fake-mpass: signed out")
        return RedirectResponse(logout_uri, status_code=302)

    return app
