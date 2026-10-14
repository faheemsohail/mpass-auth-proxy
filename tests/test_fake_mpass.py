"""fake-mpass (dev/fake-mpass) driven end to end by the real proxy in main.py.

In-process only: main's httpx calls are routed into the fake via ASGITransport,
so nothing binds a port.
"""
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient
from jwt import PyJWK

sys.path.insert(0, str(Path(__file__).parent.parent / "dev" / "fake-mpass"))
import fake_mpass  # noqa: E402

import main as m  # noqa: E402

CALLBACK = "https://test-auth.example.com/oauth2/callback"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"  # S256(VERIFIER)


@pytest.fixture(autouse=True)
def allow(monkeypatch):
    monkeypatch.setenv(fake_mpass.GUARD_VAR, "1")


@pytest.fixture
def fake():
    return TestClient(fake_mpass.create_app(issuer=m.OIDC_ISSUER_URL))


@pytest.fixture
def proxy(monkeypatch, fake):
    """The real proxy, with its IdP/JWKS traffic and Redis pointed at the fake."""
    fake_app = fake.app
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        m.httpx, "AsyncClient",
        lambda **kw: real_client(transport=httpx.ASGITransport(app=fake_app), **kw),
    )
    store: dict = {}

    class Redis:
        async def setex(self, k, ttl, v):
            store[k] = v

        async def getdel(self, k):
            return store.pop(k, None)

    async def no_overlay(_):
        return None

    monkeypatch.setattr(m, "redis_client", Redis())
    monkeypatch.setattr(m, "_lookup_real_email", no_overlay)
    monkeypatch.setattr(m, "_jwks_cache", None)
    monkeypatch.setattr(m, "_token_endpoint_cache", None)
    return TestClient(m.app, follow_redirects=False)


def sign_in(proxy, fake, user, state="s1"):
    """/authorize -> fake login -> /mpass-callback. Returns the callback response."""
    r = proxy.get("/authorize", params={
        "state": state, "redirect_uri": CALLBACK,
        "code_challenge": CHALLENGE, "code_challenge_method": "S256",
    })
    assert r.status_code == 302
    login = urlparse(r.headers["location"])
    assert login.path == "/users/login"
    page = fake.get(f"{login.path}?{login.query}")
    assert f"user={user}" in page.text
    r = fake.get(f"/users/login/as?user={user}&{login.query}", follow_redirects=False)
    cb = urlparse(r.headers["location"])
    assert f"{cb.scheme}://{cb.netloc}{cb.path}" == m.MPASS_CALLBACK_URL
    return proxy.get(f"{cb.path}?{cb.query}", cookies={"mpass_bridge": state})


def exchange(proxy, callback_resp):
    q = parse_qs(urlparse(callback_resp.headers["location"]).query)
    return proxy.post("/token", data={
        "grant_type": "authorization_code", "code": q["code"][0], "code_verifier": VERIFIER,
    })


def test_guard_refuses_without_ack(monkeypatch):
    monkeypatch.delenv(fake_mpass.GUARD_VAR)
    with pytest.raises(RuntimeError, match="refuses to start"):
        fake_mpass.create_app(issuer=m.OIDC_ISSUER_URL)


def test_discovery_and_jwks(fake):
    base = urlparse(m.OIDC_ISSUER_URL).path
    disc = fake.get(f"{base}/.well-known/openid-configuration").json()
    assert disc["issuer"] == m.EXPECTED_ISSUER
    assert disc["token_endpoint"].endswith("/oauth2/token")
    assert fake.get(f"{base}/.well-known/jwks.json").json()["keys"][0]["alg"] == "RS256"


def test_key_file_gives_stable_kid(tmp_path):
    kf = str(tmp_path / "k.pem")
    kid = lambda: TestClient(fake_mpass.create_app(issuer="http://x/p", key_file=kf)).get(
        "/p/.well-known/jwks.json").json()["keys"][0]["kid"]
    assert kid() == kid()


def test_full_flow_issues_verifiable_tokens(proxy, fake):
    cb = sign_in(proxy, fake, "alice")
    assert cb.status_code == 302 and cb.headers["location"].startswith(CALLBACK)
    tok = exchange(proxy, cb).json()
    # access_token is the fake's, verified against the fake's JWKS.
    key = PyJWK.from_dict(fake.get(urlparse(m.OIDC_ISSUER_URL).path + "/.well-known/jwks.json").json()["keys"][0]).key
    access = jwt.decode(tok["access_token"], key, algorithms=["RS256"], options={"verify_aud": False}, issuer=m.EXPECTED_ISSUER)
    assert access["username"] == "alice" and access["custom:corporate_id"] == "corp-a"
    # id_token is re-signed by the proxy (email capture on in tests/.env.test).
    ident = jwt.decode(tok["id_token"], m._SIGNING_PRIVATE_KEY.public_key(), algorithms=["RS256"], audience=m.OIDC_CLIENT_ID, options={"verify_iss": False})
    assert ident["cognito:username"] == "alice"
    assert tok["refresh_token"].startswith(fake_mpass.REFRESH_PREFIX)


@pytest.mark.parametrize("user,expected_reason", [("bob", "wrong_organization"), ("ivan", "not_corporate")])
def test_corporate_check_refuses(proxy, fake, monkeypatch, user, expected_reason):
    monkeypatch.setattr(m, "SMB_CORPORATE_ID", "corp-a")
    r = sign_in(proxy, fake, user)
    assert "login_error=access_denied" in r.headers["location"]
    assert f"reason={expected_reason}" in r.headers["location"]


@pytest.mark.parametrize("user", ["alice", "adam"])
def test_corporate_check_admits_own_org(proxy, fake, monkeypatch, user):
    monkeypatch.setattr(m, "SMB_CORPORATE_ID", "corp-a")
    assert sign_in(proxy, fake, user).headers["location"].startswith(CALLBACK)


def test_refresh(proxy, fake, monkeypatch):
    monkeypatch.setattr(m, "SMB_CORPORATE_ID", "corp-a")
    tok = exchange(proxy, sign_in(proxy, fake, "adam")).json()
    r = proxy.post("/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]})
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"] and body["id_token"]
    assert body["refresh_token"] == tok["refresh_token"]  # fake, like Cognito, does not rotate


def test_refresh_refused_for_bad_token(proxy):
    for bad in ("nope", fake_mpass.REFRESH_PREFIX + "ghost"):
        r = proxy.post("/token", data={"grant_type": "refresh_token", "refresh_token": bad})
        assert r.status_code == 400


def test_logout_redirects_to_logout_uri(fake):
    r = fake.get("/logout", params={"client_id": "c", "logout_uri": "http://localhost/bye"}, follow_redirects=False)
    assert r.headers["location"] == "http://localhost/bye"
