"""Central mode (FOSS-609): static clients, exact redirect_uri, host-only flow
cookie, client-authenticated /token, re-signed id_token. Driven end to end against
dev/stub-mpass-idp, in-process (nothing binds a port).

Central mode is switched on here by patching main._CLIENTS / issuer / logout URI;
the import-time switch (CLIENTS_FILE) is covered in TestCentralConfig.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient
from jwt import PyJWK

sys.path.insert(0, str(Path(__file__).parent.parent / "dev" / "stub-mpass-idp"))
import stub_mpass_idp  # noqa: E402

import central as c  # noqa: E402
import main as m  # noqa: E402

ISSUER = "https://test-auth.example.com"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"  # S256(VERIFIER)
IDP_LOGOUT = urlparse(m.OIDC_ISSUER_URL)._replace(path="/logout").geturl()


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


PORTAL_SECRET = "portal-secret-0123456789"
PORTAL = {
    "client_id": "foss-portal-sandbox",
    "secret_sha256": [_sha(PORTAL_SECRET)],
    "redirect_uris": ["https://portal.example.com/api/auth/mpass/callback"],
    "post_logout_redirect_uris": ["https://portal.example.com/"],
    "smb_binding": None,
}
FD_A_SECRET = "fd-a-secret-0123456789"
FD_A = {
    "client_id": "fd-a",
    "secret_sha256": [_sha("old-rotated-out"), _sha(FD_A_SECRET)],
    "redirect_uris": ["https://auth.a.example.net/oauth2/callback"],
    "post_logout_redirect_uris": [],
    "smb_binding": "corp-a",
}
SECRETS = {"foss-portal-sandbox": PORTAL_SECRET, "fd-a": FD_A_SECRET}


@pytest.fixture(autouse=True)
def allow(monkeypatch):
    monkeypatch.setenv(stub_mpass_idp.GUARD_VAR, "1")


@pytest.fixture
def stub_key_file(tmp_path):
    return tmp_path / "stub-key.pem"


@pytest.fixture
def stub(stub_key_file):
    return TestClient(stub_mpass_idp.create_app(
        issuer=m.OIDC_ISSUER_URL,
        allowed_redirects=[f"{ISSUER}/", "https://portal.example.com/"],
        key_file=str(stub_key_file),
    ))


@pytest.fixture
def idp_sign(stub, stub_key_file):
    """Sign claims with the stub IdP's own key and kid: a token the proxy's
    JWKS check accepts, so a test can vary exactly one claim."""
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_private_key(stub_key_file.read_bytes(), password=None)
    kid = stub.get(urlparse(m.OIDC_ISSUER_URL).path + "/.well-known/jwks.json").json()["keys"][0]["kid"]
    return lambda claims: jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def store():
    return {}


@pytest.fixture
def proxy(monkeypatch, stub, store):
    stub_app = stub.app
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        m.httpx, "AsyncClient",
        lambda **kw: real_client(transport=httpx.ASGITransport(app=stub_app), **kw),
    )

    class Redis:
        async def setex(self, k, ttl, v):
            store[k] = (ttl, v)

        async def getdel(self, k):
            return (store.pop(k, None) or (None, None))[1]

        async def get(self, k):
            return (store.get(k) or (None, None))[1]

        async def delete(self, k):
            store.pop(k, None)

    monkeypatch.setattr(m, "redis_client", Redis())
    monkeypatch.setattr(m, "_jwks_cache", None)
    monkeypatch.setattr(m, "_token_endpoint_cache", None)
    monkeypatch.setattr(m, "_CLIENTS", c._parse_clients({"clients": [PORTAL, FD_A]}))
    monkeypatch.setattr(m, "MPASS_PROXY_ISSUER_URL", ISSUER)
    monkeypatch.setattr(m, "OIDC_LOGOUT_URI", IDP_LOGOUT)
    return TestClient(m.app, base_url=ISSUER, follow_redirects=False)


def authorize(proxy, client=PORTAL, **over):
    params = {
        "client_id": client["client_id"], "redirect_uri": client["redirect_uris"][0],
        "state": "caller-state", "code_challenge": CHALLENGE, "code_challenge_method": "S256",
        **over,
    }
    return proxy.get("/authorize", params={k: v for k, v in params.items() if v is not None})


def idp_login(stub, authorize_resp, user):
    """Follow the hosted-login redirect; return the IdP's redirect to /mpass-callback."""
    login = urlparse(authorize_resp.headers["location"])
    q = parse_qs(login.query)
    r = stub.get("/users/login/as", params={
        "user": user, "client_id": q["client_id"][0], "client_redirect_url": q["client_redirect_url"][0],
    }, follow_redirects=False)
    return urlparse(r.headers["location"])


def sign_in(proxy, stub, user, client=PORTAL, **over):
    r = authorize(proxy, client, **over)
    assert r.status_code == 302, r.text
    cb = idp_login(stub, r, user)
    assert f"{cb.scheme}://{cb.netloc}{cb.path}" == m.MPASS_CALLBACK_URL
    return proxy.get(f"{cb.path}?{cb.query}")


def code_of(resp):
    return parse_qs(urlparse(resp.headers["location"]).query)["code"][0]


def token(proxy, code, client=PORTAL, secret=None, how="basic", **over):
    cid = client["client_id"]
    secret = SECRETS[cid] if secret is None else secret
    data = {"grant_type": "authorization_code", "code": code, "code_verifier": VERIFIER,
            "redirect_uri": client["redirect_uris"][0]}
    headers = {}
    if how == "basic":
        raw = f"{quote(cid, safe='')}:{quote(secret, safe='')}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    elif how == "post":
        data.update(client_id=cid, client_secret=secret)
    data.update(over)
    return proxy.post("/token", data={k: v for k, v in data.items() if v is not None}, headers=headers)


def refused(r, status=400):
    return r.status_code == status and "location" not in r.headers


def proxy_key(proxy):
    jwks = proxy.get("/.well-known/jwks.json").json()
    return PyJWK.from_dict(jwks["keys"][0]).key


# ---------------------------------------------------------------------------
# /authorize
# ---------------------------------------------------------------------------

class TestAuthorizeRefusals:
    def test_missing_client_id(self, proxy):
        assert refused(authorize(proxy, client_id=None))

    def test_unknown_client_id(self, proxy):
        assert refused(authorize(proxy, client_id="fd-nope"))

    @pytest.mark.parametrize("uri", [
        None,
        "",
        "https://portal.example.com/api/auth/mpass/callback/",       # trailing slash
        "https://portal.example.com/api/auth/mpass/callback?x=1",    # extra query
        "https://portal.example.com/api/auth/mpass/callbac",         # prefix
        "https://portal.example.com/api/auth/mpass",                 # parent
        "http://portal.example.com/api/auth/mpass/callback",         # scheme
        "https://PORTAL.example.com/api/auth/mpass/callback",        # not byte-equal
        "https://portal.example.com:443/api/auth/mpass/callback",    # explicit port
        "https://evil.com/api/auth/mpass/callback",
        "https://auth.a.example.net/oauth2/callback",                # another client's
    ])
    def test_redirect_uri_not_exactly_registered(self, proxy, uri):
        assert refused(authorize(proxy, redirect_uri=uri))

    @pytest.mark.parametrize("uri", [
        "https://evil.com@portal.example.com/api/auth/mpass/callback",
        "https://portal.example.com\\@evil.com/api/auth/mpass/callback",
        "https://portal.example.com/api\\auth/mpass/callback",
        "https://portal.example.com/api/auth/mpass/callback#frag",
        "https://portal.example.com/api/auth/mpass/callback#",
        "https://portal.example.com/api/auth/x/../mpass/callback",
        "https://portal.example.com/api/auth/x/%2e%2e/mpass/callback",
        "https://portal.example.com/api/auth/./mpass/callback",
    ])
    def test_redirect_uri_fails_strict_parse(self, proxy, uri):
        assert refused(authorize(proxy, redirect_uri=uri))

    @pytest.mark.parametrize("uri", [
        "https://evil.com@portal.example.com/api/auth/mpass/callback",
        "https://portal.example.com\\@evil.com/api/auth/mpass/callback",
        "https://portal.example.com/api\\auth/mpass/callback",
        "https://portal.example.com/api/auth/mpass/callback#frag",
        "https://portal.example.com/api/auth/x/../mpass/callback",
        "https://portal.example.com/api/auth/x/%2E%2E/mpass/callback",
    ])
    def test_strict_parse_refuses_even_if_registered(self, uri):
        # The exact match alone would let a bad URI through if one were ever
        # registered; the parse is applied on its own, and at config load.
        assert not c._strict_redirect_uri_ok(uri)
        with pytest.raises(RuntimeError):
            c._parse_clients({"clients": [{**PORTAL, "redirect_uris": [uri]}]})

    def test_missing_code_challenge(self, proxy):
        assert refused(authorize(proxy, code_challenge=None))

    def test_missing_challenge_method_is_plain_and_refused(self, proxy):
        assert refused(authorize(proxy, code_challenge_method=None))

    def test_plain_challenge_method(self, proxy):
        assert refused(authorize(proxy, code_challenge_method="plain", code_challenge=VERIFIER))

    @pytest.mark.parametrize("challenge", ["short", CHALLENGE + "A", CHALLENGE[:-1] + "="])
    def test_malformed_challenge(self, proxy, challenge):
        assert refused(authorize(proxy, code_challenge=challenge))

    def test_missing_state(self, proxy):
        assert refused(authorize(proxy, state=None))

    def test_refusal_stores_nothing(self, proxy, store):
        authorize(proxy, client_id="fd-nope")
        assert store == {}


class TestAuthorizeAccepts:
    def test_redirects_to_hosted_login_with_central_callback(self, proxy):
        r = authorize(proxy)
        assert r.status_code == 302
        loc = urlparse(r.headers["location"])
        assert f"{loc.scheme}://{loc.netloc}{loc.path}" == f"{m.MONETA_HOSTED_UI_URL}/users/login"
        q = parse_qs(loc.query)
        assert q["client_id"] == [m.OIDC_CLIENT_ID]
        assert q["client_redirect_url"] == [m.MPASS_CALLBACK_URL]

    def test_flow_cookie_is_host_only(self, proxy):
        r = authorize(proxy)
        sc = r.headers["set-cookie"]
        assert sc.startswith("__Host-mpass_flow=")
        attrs = {a.strip().split("=")[0].lower() for a in sc.split(";")[1:]}
        assert {"secure", "httponly", "path"} <= attrs
        assert "domain" not in attrs
        assert "Path=/" in sc and "SameSite=lax" in sc
        assert "mpass_bridge" not in sc

    def test_flow_keyed_by_proxy_generated_id_not_callers_state(self, proxy, store):
        r = authorize(proxy, state="caller-state")
        flow_id = r.cookies["__Host-mpass_flow"]
        assert flow_id != "caller-state" and len(flow_id) >= 32
        assert list(store) == [f"central_flow:{flow_id}"]
        ttl, raw = store[f"central_flow:{flow_id}"]
        assert ttl == m.BRIDGE_STATE_TTL
        assert json.loads(raw)["client_id"] == "foss-portal-sandbox"

    def test_two_flows_with_same_state_do_not_collide(self, proxy, store):
        a = authorize(proxy, state="same").cookies["__Host-mpass_flow"]
        b = authorize(proxy, FD_A, state="same").cookies["__Host-mpass_flow"]
        assert a != b and len(store) == 2


# ---------------------------------------------------------------------------
# /mpass-callback
# ---------------------------------------------------------------------------

class TestCallback:
    def test_issues_code_to_registered_uri_with_callers_state(self, proxy, stub, store):
        r = sign_in(proxy, stub, "bob")  # portal is unbound: any corporate user
        assert r.status_code == 302
        loc = urlparse(r.headers["location"])
        assert f"{loc.scheme}://{loc.netloc}{loc.path}" == PORTAL["redirect_uris"][0]
        q = parse_qs(loc.query)
        assert q["state"] == ["caller-state"]
        ttl, raw = store[f"central_code:{q['code'][0]}"]
        assert ttl == 60
        data = json.loads(raw)
        assert data["client_id"] == "foss-portal-sandbox"
        assert data["redirect_uri"] == PORTAL["redirect_uris"][0]
        assert data["code_challenge"] == CHALLENGE
        # No Cognito id or access token is kept. The refresh token is kept
        # server-side, under a name no response uses (FOSS-611).
        assert not {"id_token", "access_token", "refresh_token"} & set(data)
        assert data["idp_refresh_token"] == "stub-refresh:bob"

    def test_clears_flow_cookie(self, proxy, stub):
        sc = sign_in(proxy, stub, "alice").headers["set-cookie"]
        assert sc.startswith('__Host-mpass_flow=""') or "Max-Age=0" in sc
        assert "Secure" in sc and "Domain" not in sc

    def test_no_flow_cookie(self, proxy, stub):
        cb = idp_login(stub, authorize(proxy), "alice")
        proxy.cookies.clear()
        assert refused(proxy.get(f"{cb.path}?{cb.query}"))

    def test_callers_state_is_not_a_flow_key(self, proxy, stub):
        cb = idp_login(stub, authorize(proxy, state="guessable"), "alice")
        proxy.cookies.clear()
        proxy.cookies.set("__Host-mpass_flow", "guessable")
        assert refused(proxy.get(f"{cb.path}?{cb.query}"))

    def test_flow_is_single_use(self, proxy, stub):
        r = authorize(proxy)
        flow = r.cookies["__Host-mpass_flow"]
        cb = idp_login(stub, r, "alice")
        assert proxy.get(f"{cb.path}?{cb.query}").status_code == 302
        proxy.cookies.set("__Host-mpass_flow", flow)
        assert refused(proxy.get(f"{cb.path}?{cb.query}"))

    def test_legacy_bridge_cookie_is_ignored(self, proxy, stub, store):
        r = authorize(proxy)
        cb = idp_login(stub, r, "alice")
        proxy.cookies.clear()
        proxy.cookies.set("mpass_bridge", "caller-state")
        assert refused(proxy.get(f"{cb.path}?{cb.query}"))

    @pytest.mark.parametrize("user,reason", [("bob", "wrong_organization"), ("ivan", "not_corporate")])
    def test_bound_client_refuses_other_smb(self, proxy, stub, store, user, reason):
        r = sign_in(proxy, stub, user, FD_A)
        loc = urlparse(r.headers["location"])
        assert f"{loc.scheme}://{loc.netloc}{loc.path}" == FD_A["redirect_uris"][0]
        q = parse_qs(loc.query)
        assert q["error"] == ["access_denied"] and q["state"] == ["caller-state"]
        assert "code" not in q
        assert not any(k.startswith("central_code:") for k in store)
        assert reason in q["error_description"][0]

    def test_bound_client_admits_own_smb(self, proxy, stub):
        assert "code" in parse_qs(urlparse(sign_in(proxy, stub, "adam", FD_A).headers["location"]).query)

    def test_global_smb_setting_is_not_used(self, proxy, stub, monkeypatch):
        monkeypatch.setattr(m, "SMB_CORPORATE_ID", "corp-b")
        assert "code" in parse_qs(urlparse(sign_in(proxy, stub, "alice", FD_A).headers["location"]).query)

    def test_forged_id_token_refused(self, proxy, stub):
        r = authorize(proxy)
        cb = idp_login(stub, r, "alice")
        q = parse_qs(cb.query)
        forged = jwt.encode(jwt.decode(q["id_token"][0], options={"verify_signature": False}),
                            m._SIGNING_PRIVATE_KEY, algorithm="RS256", headers={"kid": "x"})
        r = proxy.get(cb.path, params={**{k: v[0] for k, v in q.items()}, "id_token": forged})
        assert refused(r, 401)

    def test_forged_access_token_refused_for_unbound_client(self, proxy, stub):
        # The portal reads the corporate claims we copy, so they must come from
        # a verified token even when the client has no SMB binding.
        r = authorize(proxy)
        cb = idp_login(stub, r, "alice")
        q = parse_qs(cb.query)
        claims = jwt.decode(q["access_token"][0], options={"verify_signature": False})
        forged = jwt.encode({**claims, "custom:corporate_id": "corp-b"},
                            m._SIGNING_PRIVATE_KEY, algorithm="RS256", headers={"kid": "x"})
        r = proxy.get(cb.path, params={**{k: v[0] for k, v in q.items()}, "access_token": forged})
        assert refused(r, 401)

    def test_missing_access_token_refused(self, proxy, stub):
        cb = idp_login(stub, authorize(proxy), "alice")
        q = {k: v[0] for k, v in parse_qs(cb.query).items() if k != "access_token"}
        assert refused(proxy.get(cb.path, params=q), 502)


# ---------------------------------------------------------------------------
# /token
# ---------------------------------------------------------------------------

def _err(r):
    return r.json()["error"]


class TestTokenRefusals:
    @pytest.fixture
    def code(self, proxy, stub):
        return code_of(sign_in(proxy, stub, "alice"))

    def test_no_client_authentication(self, proxy, code):
        r = token(proxy, code, how=None)
        assert r.status_code == 401 and _err(r) == "invalid_client"

    @pytest.mark.parametrize("how", ["basic", "post"])
    def test_wrong_secret(self, proxy, code, how):
        r = token(proxy, code, secret="wrong", how=how)
        assert r.status_code == 401 and _err(r) == "invalid_client"

    def test_either_rotation_secret_accepted(self, proxy, stub):
        code = code_of(sign_in(proxy, stub, "alice", FD_A))
        assert token(proxy, code, FD_A, secret="old-rotated-out").status_code == 200

    def test_unknown_client(self, proxy, code):
        r = token(proxy, code, {"client_id": "fd-ghost", "redirect_uris": PORTAL["redirect_uris"]}, secret="x")
        assert r.status_code == 401 and _err(r) == "invalid_client"

    def test_malformed_basic_header(self, proxy, code):
        r = proxy.post("/token", headers={"Authorization": "Basic !!!"},
                       data={"grant_type": "authorization_code", "code": code})
        assert r.status_code == 401 and _err(r) == "invalid_client"

    def test_two_auth_methods(self, proxy, code):
        r = token(proxy, code, how="basic", client_id=PORTAL["client_id"], client_secret=PORTAL_SECRET)
        assert r.status_code == 400 and _err(r) == "invalid_request"

    def test_code_issued_to_another_client(self, proxy, stub):
        code = code_of(sign_in(proxy, stub, "alice", FD_A))
        r = token(proxy, code, PORTAL, redirect_uri=FD_A["redirect_uris"][0])
        assert r.status_code == 400 and _err(r) == "invalid_grant"

    @pytest.mark.parametrize("uri", [None, "", "https://portal.example.com/other"])
    def test_redirect_uri_mismatch(self, proxy, code, uri):
        r = token(proxy, code, redirect_uri=uri)
        assert r.status_code == 400 and _err(r) == "invalid_grant"

    @pytest.mark.parametrize("verifier", [None, "", "x" * 43])
    def test_bad_verifier(self, proxy, code, verifier):
        r = token(proxy, code, code_verifier=verifier)
        assert r.status_code == 400 and _err(r) == "invalid_grant"

    def test_code_single_use(self, proxy, code):
        assert token(proxy, code).status_code == 200
        r = token(proxy, code)
        assert r.status_code == 400 and _err(r) == "invalid_grant"

    def test_failed_redemption_burns_the_code(self, proxy, code):
        assert token(proxy, code, code_verifier="x" * 43).status_code == 400
        assert token(proxy, code).status_code == 400

    def test_expired_code(self, proxy, code, store):
        store.clear()  # what Redis does after the 60 s setex TTL
        assert _err(token(proxy, code)) == "invalid_grant"

    def test_unknown_code(self, proxy):
        assert _err(token(proxy, "nope")) == "invalid_grant"

    def test_raw_idp_refresh_token_refused(self, proxy, code):
        # Refresh exists since FOSS-611, but only for this service's handles.
        r = token(proxy, code, grant_type="refresh_token", refresh_token="stub-refresh:alice")
        assert r.status_code == 400 and _err(r) == "invalid_grant"

    def test_unknown_grant_type(self, proxy, code):
        r = token(proxy, code, grant_type="password")
        assert r.status_code == 400 and _err(r) == "unsupported_grant_type"

    def test_refresh_grant_needs_client_auth_first(self, proxy):
        r = proxy.post("/token", data={"grant_type": "refresh_token", "refresh_token": "stub-refresh:alice"})
        assert r.status_code == 401


class TestTokenIssues:
    @pytest.mark.parametrize("how", ["basic", "post"])
    def test_resigned_id_token(self, proxy, stub, how):
        r = token(proxy, code_of(sign_in(proxy, stub, "alice", nonce="n-123")), how=how)
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body) == {"access_token", "id_token", "token_type", "expires_in", "refresh_token"}
        claims = jwt.decode(body["id_token"], proxy_key(proxy), algorithms=["RS256"],
                            audience="foss-portal-sandbox", issuer=ISSUER)
        assert claims["cognito:username"] == "alice"
        assert claims["email"] == "alice@corp-a.example.com"
        assert claims["custom:is_corporate"] == "true"
        assert claims["custom:corporate_id"] == "corp-a"
        assert claims["nonce"] == "n-123"
        assert claims["sub"] and claims["exp"] > claims["iat"]
        assert jwt.get_unverified_header(body["id_token"])["kid"] == m._SIGNING_KID

    def test_no_cognito_tokens_forwarded(self, proxy, stub):
        body = token(proxy, code_of(sign_in(proxy, stub, "alice"))).json()
        # The refresh token is this service's opaque handle, not Cognito's (FOSS-611).
        assert "stub-refresh:" not in json.dumps(body)
        # The access token is ours, for this client, not Cognito's.
        a = jwt.decode(body["access_token"], proxy_key(proxy), algorithms=["RS256"],
                       audience="foss-portal-sandbox", issuer=ISSUER)
        assert a["token_use"] == "access" and "client_id" not in a

    def test_individual_user_on_unbound_client_carries_false(self, proxy, stub):
        body = token(proxy, code_of(sign_in(proxy, stub, "ivan"))).json()
        claims = jwt.decode(body["id_token"], options={"verify_signature": False})
        assert claims["custom:is_corporate"] == "false" and "custom:corporate_id" not in claims

    def test_audience_is_per_client(self, proxy, stub):
        body = token(proxy, code_of(sign_in(proxy, stub, "alice", FD_A)), FD_A).json()
        with pytest.raises(jwt.InvalidAudienceError):
            jwt.decode(body["id_token"], proxy_key(proxy), algorithms=["RS256"],
                       audience="foss-portal-sandbox", issuer=ISSUER)


# ---------------------------------------------------------------------------
# Discovery, JWKS, logout
# ---------------------------------------------------------------------------

class TestDiscovery:
    def test_openid_configuration(self, proxy):
        d = proxy.get("/.well-known/openid-configuration").json()
        assert d["issuer"] == ISSUER
        assert d["authorization_endpoint"] == f"{ISSUER}/authorize"
        assert d["token_endpoint"] == f"{ISSUER}/token"
        assert d["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"
        assert d["end_session_endpoint"] == f"{ISSUER}/logout"
        assert d["code_challenge_methods_supported"] == ["S256"]
        assert d["grant_types_supported"] == ["authorization_code", "refresh_token"]
        assert set(d["token_endpoint_auth_methods_supported"]) == {"client_secret_basic", "client_secret_post"}

    def test_jwks_served_even_with_email_capture_off(self, proxy, monkeypatch):
        monkeypatch.setattr(m, "_EMAIL_CAPTURE_ENABLED", False)
        assert proxy.get("/.well-known/jwks.json").json()["keys"][0]["kid"] == m._SIGNING_KID


class TestLogout:
    def logout(self, proxy, **over):
        params = {"client_id": PORTAL["client_id"], "post_logout_redirect_uri": "https://portal.example.com/", **over}
        return proxy.get("/logout", params={k: v for k, v in params.items() if v is not None})

    @pytest.mark.parametrize("over", [
        {"client_id": None}, {"client_id": "fd-ghost"},
        {"post_logout_redirect_uri": None},
        {"post_logout_redirect_uri": "https://portal.example.com/x"},
        {"post_logout_redirect_uri": "https://evil.com/"},
        {"post_logout_redirect_uri": "https://portal.example.com/#"},
        {"client_id": "fd-a"},  # fd-a registers no logout URIs
    ])
    def test_refusals(self, proxy, over):
        assert refused(self.logout(proxy, **over))

    def test_chains_through_idp_and_back(self, proxy, stub):
        r = self.logout(proxy)
        assert r.status_code == 302
        sc = r.headers["set-cookie"]
        assert sc.startswith("__Host-mpass_logout=") and "Secure" in sc and "Domain" not in sc
        idp = urlparse(r.headers["location"])
        assert f"{idp.scheme}://{idp.netloc}{idp.path}" == IDP_LOGOUT
        q = parse_qs(idp.query)
        assert q["client_id"] == [m.OIDC_CLIENT_ID]
        assert q["logout_uri"] == [f"{ISSUER}/signed-out"]
        back = urlparse(stub.get(f"{idp.path}?{idp.query}", follow_redirects=False).headers["location"])
        r = proxy.get(back.path)
        assert r.status_code == 302 and r.headers["location"] == "https://portal.example.com/"

    def test_signed_out_without_cookie_does_not_redirect(self, proxy):
        assert proxy.get("/signed-out").status_code == 200
        assert "location" not in proxy.get("/signed-out").headers

    def test_signed_out_revalidates_a_tampered_cookie(self, proxy):
        val = base64.urlsafe_b64encode(json.dumps(
            {"client_id": PORTAL["client_id"], "uri": "https://evil.com/"}).encode()).decode()
        proxy.cookies.set("__Host-mpass_logout", val)
        assert "location" not in proxy.get("/signed-out").headers

    def test_legacy_login_logout_routes_off(self, proxy):
        assert proxy.get("/mpass/login").status_code == 404
        assert proxy.get("/mpass/logout").status_code == 404


class TestBundleModeUnchanged:
    """With _CLIENTS empty (CLIENTS_FILE unset) the new routes do not exist."""

    @pytest.mark.parametrize("path", ["/logout", "/signed-out", "/.well-known/openid-configuration"])
    def test_new_routes_404(self, path):
        assert m._CLIENTS == {}
        assert TestClient(m.app).get(path).status_code == 404


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _rsa_b64() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return base64.b64encode(pem).decode()


_KEY_B64 = _rsa_b64()


class TestCentralConfig:
    def test_example_file_loads(self):
        clients = c._load_clients(str(Path(c.__file__).with_name("clients.example.json")))
        assert clients["foss-portal-sandbox"]["smb_binding"] is None

    @pytest.mark.parametrize("bad", [
        {"clients": []},
        {"clients": [{**PORTAL, "client_id": ""}]},
        {"clients": [PORTAL, PORTAL]},
        {"clients": [{**PORTAL, "secret_sha256": []}]},
        {"clients": [{**PORTAL, "secret_sha256": ["abc"]}]},
        {"clients": [{**PORTAL, "secret_sha256": [_sha("x").upper()]}]},
        {"clients": [{**PORTAL, "redirect_uris": []}]},
        {"clients": [{**PORTAL, "redirect_uris": ["javascript:alert(1)"]}]},
        {"clients": [{**PORTAL, "post_logout_redirect_uris": ["https://a@b/"]}]},
        {"clients": [{k: v for k, v in PORTAL.items() if k != "smb_binding"}]},
        {"clients": [{**PORTAL, "smb_binding": ""}]},
        {"clients": [{**PORTAL, "extra": 1}]},
    ])
    def test_bad_config_refuses_to_start(self, bad):
        with pytest.raises(RuntimeError):
            c._parse_clients(bad)

    def _import(self, monkeypatch, tmp_path, **env):
        import importlib
        f = tmp_path / "clients.json"
        f.write_text(json.dumps({"clients": [PORTAL]}))
        monkeypatch.setenv("CLIENTS_FILE", str(f))
        monkeypatch.setenv("MPASS_PROXY_ISSUER_URL", ISSUER)
        monkeypatch.setenv("OIDC_LOGOUT_URI", IDP_LOGOUT)
        monkeypatch.delenv("COOKIE_DOMAIN", raising=False)  # not needed centrally
        monkeypatch.setenv("MPASS_SIGNING_KEY_ALLOW_EPHEMERAL", "false")
        monkeypatch.setenv("MPASS_SIGNING_KEY_B64", _KEY_B64)
        for k, v in env.items():
            if v is None:
                monkeypatch.delenv(k, raising=False)
            else:
                monkeypatch.setenv(k, v)
        sys.modules.pop("main", None)
        try:
            return importlib.import_module("main")
        finally:
            sys.modules["main"] = m

    def test_clients_file_turns_central_mode_on(self, monkeypatch, tmp_path):
        mod = self._import(monkeypatch, tmp_path, LAUNCHPAD_EMAIL_CAPTURE="false")
        assert set(mod._CLIENTS) == {"foss-portal-sandbox"}
        assert mod._SIGNING_PRIVATE_KEY is not None  # central mode always signs

    @pytest.mark.parametrize("env", [
        {"MPASS_PROXY_ISSUER_URL": None},
        {"MPASS_PROXY_ISSUER_URL": "http://mpass-auth-proxy:8000"},
        {"OIDC_LOGOUT_URI": None},
        {"SMB_CORPORATE_ID": "corp-a"},
        # Replicas must share one key (Plan 3 §2), so the dev-only opt-in is
        # refused centrally even when a real key is also configured.
        {"MPASS_SIGNING_KEY_ALLOW_EPHEMERAL": "true"},
        {"MPASS_SIGNING_KEY_ALLOW_EPHEMERAL": "true", "MPASS_SIGNING_KEY_B64": ""},
    ])
    def test_central_mode_refuses_incomplete_config(self, monkeypatch, tmp_path, env):
        with pytest.raises(RuntimeError):
            self._import(monkeypatch, tmp_path, **env)


# ---------------------------------------------------------------------------
# Security review of PR #11
# ---------------------------------------------------------------------------

class TestLoginSwap:
    """The IdP leg carries no state, so a captured /mpass-callback URL (the
    attacker's own token pair) could complete a victim's unfinished flow. The
    stopgap: tokens minted before the flow began, beyond clock skew, are refused."""

    def test_captured_callback_refused_in_a_later_flow(self, proxy, stub, monkeypatch, store):
        attacker_cb = idp_login(stub, authorize(proxy), "bob")   # attacker signs in, keeps the URL
        proxy.cookies.clear()
        later = m.time.time() + c.FLOW_TOKEN_SKEW + 5
        monkeypatch.setattr(m.time, "time", lambda: later)
        authorize(proxy)                                          # victim starts a flow
        r = proxy.get(f"{attacker_cb.path}?{attacker_cb.query}")  # ...and follows the link
        assert refused(r, 401)
        assert not any(k.startswith("central_code:") for k in store)

    def test_tokens_within_skew_accepted(self, proxy, stub, monkeypatch):
        # The proxy's clock runs ahead of the IdP's by just under the skew, so
        # honest tokens look slightly older than the flow.
        real = m.time.time
        monkeypatch.setattr(m.time, "time", lambda: real() + c.FLOW_TOKEN_SKEW - 5)
        r = authorize(proxy)
        monkeypatch.setattr(m.time, "time", real)
        cb = idp_login(stub, r, "alice")
        assert "code" in parse_qs(urlparse(proxy.get(f"{cb.path}?{cb.query}").headers["location"]).query)

    @pytest.mark.parametrize("iat,ok", [
        (None, False), ("1000", False), (True, False),
        (1000 - 61, False), (1000 - 60, True), (1000, True), (2000, True),
    ])
    def test_iat_rule(self, iat, ok, monkeypatch):
        monkeypatch.setattr(c, "FLOW_TOKEN_SKEW", 60)
        claims = {} if iat is None else {"iat": iat}
        assert c._minted_during_flow(claims, 1000) is ok

    def test_flow_records_creation_time(self, proxy, store):
        before = int(m.time.time())
        authorize(proxy)
        (ttl, raw), = store.values()
        assert before <= json.loads(raw)["created_at"] <= int(m.time.time())

    def test_stub_hosted_login_echoes_nothing_to_bind_to(self, proxy, stub):
        """No flow binding is possible today: the hosted login takes only
        client_id and client_redirect_url, and returns no state or nonce. The
        real fix needs mPass to round-trip one (FOSS-616)."""
        login = urlparse(authorize(proxy, nonce="n-1").headers["location"])
        assert set(parse_qs(login.query)) == {"client_id", "client_redirect_url"}
        q = parse_qs(login.query)
        r = stub.get("/users/login/as", params={"user": "alice", "client_id": q["client_id"][0],
                     "client_redirect_url": q["client_redirect_url"][0], "state": "s", "nonce": "n"},
                     follow_redirects=False)
        back = parse_qs(urlparse(r.headers["location"]).query)
        assert set(back) == {"id_token", "access_token", "refresh_token"}
        assert "nonce" not in jwt.decode(back["id_token"][0], options={"verify_signature": False})


class TestTokenTypes:
    def test_access_token_is_typed_at_jwt(self, proxy, stub):
        body = token(proxy, code_of(sign_in(proxy, stub, "alice"))).json()
        assert jwt.get_unverified_header(body["access_token"])["typ"] == "at+jwt"
        assert jwt.get_unverified_header(body["id_token"])["typ"] == "JWT"


def test_central_token_never_logs_the_verifier(proxy, stub, caplog):
    caplog.set_level("DEBUG")
    code = code_of(sign_in(proxy, stub, "alice"))
    bad = "y" * 43
    token(proxy, code, code_verifier=bad)
    assert bad not in caplog.text and VERIFIER not in caplog.text


# ---------------------------------------------------------------------------
# Code review of PR #11: guards a mutation showed were unpinned
# ---------------------------------------------------------------------------

def _callback_with(proxy, stub, idp_sign, id_over=None, access_over=None, drop=()):
    """Run a real flow, then replace the IdP's tokens with copies re-signed by
    the IdP's key with the given claim changes."""
    cb = idp_login(stub, authorize(proxy), "alice")
    q = {k: v[0] for k, v in parse_qs(cb.query).items()}
    for name, over in (("id_token", id_over), ("access_token", access_over)):
        claims = {**jwt.decode(q[name], options={"verify_signature": False}), **(over or {})}
        q[name] = idp_sign({k: v for k, v in claims.items() if k not in drop})
    return proxy.get(cb.path, params=q)


class TestCallbackTokenChecks:
    def test_unchanged_resigned_pair_accepted(self, proxy, stub, idp_sign):
        # Control: the re-signing helper alone does not cause a refusal.
        assert "code" in parse_qs(urlparse(_callback_with(proxy, stub, idp_sign).headers["location"]).query)

    def test_id_token_for_another_audience(self, proxy, stub, idp_sign):
        assert refused(_callback_with(proxy, stub, idp_sign, id_over={"aud": "some-other-client"}), 401)

    def test_access_token_with_wrong_token_use(self, proxy, stub, idp_sign):
        assert refused(_callback_with(proxy, stub, idp_sign, access_over={"token_use": "id"}), 401)

    def test_access_token_for_another_cognito_client(self, proxy, stub, idp_sign):
        assert refused(_callback_with(proxy, stub, idp_sign, access_over={"client_id": "other"}), 401)

    def test_tokens_without_sub(self, proxy, stub, idp_sign):
        assert refused(_callback_with(proxy, stub, idp_sign, drop=("sub",)), 401)

    def test_client_deregistered_mid_flow(self, proxy, stub, monkeypatch):
        r = authorize(proxy, FD_A)
        cb = idp_login(stub, r, "alice")
        monkeypatch.setattr(m, "_CLIENTS", c._parse_clients({"clients": [PORTAL]}))
        assert refused(proxy.get(f"{cb.path}?{cb.query}"))


class TestReviewGuards:
    def test_basic_and_form_client_id_must_agree(self, proxy, stub):
        code = code_of(sign_in(proxy, stub, "alice"))
        r = token(proxy, code, how="basic", client_id="fd-a")
        assert r.status_code == 401 and _err(r) == "invalid_client"

    def test_basic_with_matching_form_client_id_accepted(self, proxy, stub):
        code = code_of(sign_in(proxy, stub, "alice"))
        assert token(proxy, code, how="basic", client_id=PORTAL["client_id"]).status_code == 200

    @pytest.mark.parametrize("uri", [
        "https://portal%2eexample.com/cb",
        "https://portal.example.com%40evil.com/cb",
    ])
    def test_percent_in_authority(self, uri):
        assert c._strict_redirect_uri_ok(uri) is False

    @pytest.mark.parametrize("uri", ["https://portal.example.com:abc/cb", "https://portal.example.com:99999/cb"])
    def test_bad_port_is_a_refusal_not_a_crash(self, uri):
        assert c._strict_redirect_uri_ok(uri) is False

    def test_bad_port_at_authorize(self, proxy):
        assert refused(authorize(proxy, redirect_uri="https://portal.example.com:abc/api/auth/mpass/callback"))

    @pytest.mark.parametrize("verifier", ["short", "a" * 129, "has space" + "a" * 40, "plus+" + "a" * 40])
    def test_verifier_outside_rfc7636_format(self, proxy, stub, verifier):
        # The challenge matches the verifier, so only the format check refuses.
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        code = code_of(sign_in(proxy, stub, "alice", code_challenge=challenge))
        r = token(proxy, code, code_verifier=verifier)
        assert r.status_code == 400 and _err(r) == "invalid_grant"

    @pytest.mark.parametrize("param", ["state", "nonce"])
    def test_overlong_state_or_nonce(self, proxy, store, param):
        assert refused(authorize(proxy, **{param: "x" * (c.MAX_PARAM_LEN + 1)}))
        assert store == {}

    @pytest.mark.parametrize("param", ["state", "nonce"])
    def test_state_or_nonce_at_cap_accepted(self, proxy, param):
        assert authorize(proxy, **{param: "x" * c.MAX_PARAM_LEN}).status_code == 302


@pytest.mark.parametrize("which", ["id", "access"])
def test_each_token_must_postdate_the_flow(proxy, stub, idp_sign, which):
    """Either token alone, minted before the flow began, is refused: an attacker
    could otherwise pair one stale captured token with one fresh one."""
    old = {"iat": int(m.time.time()) - c.FLOW_TOKEN_SKEW - 30}
    r = _callback_with(proxy, stub, idp_sign, **{f"{which}_over": old})
    assert refused(r, 401)
