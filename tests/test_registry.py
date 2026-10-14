"""Central mode, part 2 (FOSS-611): per-deployment clients from Fleet's registry.

Static clients (CLIENTS_FILE) are looked up first; `fd-` ids go to a fake Fleet
(`GET /internal/auth/clients/{client_id}`, Plan 3 §4.1), reached through the
same in-process transport as dev/stub-mpass-idp. Nothing binds a port.
"""
import json
import logging
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jsonschema
import jwt
import pytest
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

import central as c
import main as m
from tests.test_central import (  # noqa: F401  (fixtures are used by name)
    ISSUER, PORTAL, _sha, allow, authorize, code_of, idp_login, idp_sign, proxy, proxy_key,
    refused, sign_in, store, stub, stub_key_file, token,
)

FLEET_HOST = "fleet.test"
BROKER_TOKEN = "broker-token-for-tests"
SECRET_1, SECRET_2 = "fd-1-secret-0123456789", "fd-2-secret-0123456789"
BASE_1, BASE_2 = "d1.foss.example.net", "d2.foss.example.net"
ID1, ID2, ID9 = "fd-11111111-1111-4111-8111-111111111111", "fd-22222222-2222-4222-8222-222222222222", "fd-99999999-9999-4999-8999-999999999999"
FD1 = {"client_id": ID1, "redirect_uris": [f"https://auth.{BASE_1}/oauth2/callback"]}
FD2 = {"client_id": ID2, "redirect_uris": [f"https://auth.{BASE_2}/oauth2/callback"]}


CONTRACT = yaml.safe_load((Path(__file__).parent / "contracts" / "FOSS-611.openapi.yaml").read_text())


def schema_errors(doc, name):
    """Validation errors of doc against the frozen contract's schema `name`."""
    schema = {**CONTRACT["components"]["schemas"][name], "components": CONTRACT["components"]}
    return list(jsonschema.Draft202012Validator(schema).iter_errors(doc))


def contract_ok(resp, name):
    """The honest fake Fleet only serves what the frozen contract allows, so a
    contract change that this proxy has not followed breaks the build here."""
    errors = schema_errors(json.loads(resp.body), name)
    assert not errors, f"fake Fleet drifted from contracts/FOSS-611: {errors[0].message}"
    return resp


def entry(cid=ID1, smb="corp-a", base=BASE_1, scheme="https", state="active", secret=SECRET_1):
    return {"client_id": cid, "deployment_id": cid[3:], "smb_id": smb, "base_domain": base,
            "scheme": scheme, "state": state, "secret_sha256": [_sha(secret)]}


class FakeFleet:
    def __init__(self):
        self.entries: dict[str, dict] = {}
        self.calls = 0
        self.down = False          # connection refused
        self.status: int | None = None  # answer every lookup with this status
        self.body = None           # answer every lookup with this JSON body
        self.status_body = None    # (status, JSON body) for every lookup
        self.app = FastAPI()

        @self.app.get("/internal/auth/clients/{client_id}")
        def lookup(client_id: str, request: Request):
            if request.headers.get("authorization") != f"Bearer {BROKER_TOKEN}":
                return Response(status_code=401)
            if self.status:
                return Response(status_code=self.status)
            if self.status_body:
                return JSONResponse(self.status_body[1], status_code=self.status_body[0])
            if self.body is not None:
                return JSONResponse(self.body)
            e = self.entries.get(client_id)
            if e is None:
                return contract_ok(JSONResponse({"error": "unknown_client"}, status_code=404), "AuthClientNotFound")
            if e == "no_base_domain":
                return contract_ok(JSONResponse({"error": e}, status_code=404), "AuthClientNotFound")
            return contract_ok(JSONResponse(e), "AuthClientOut")

        @self.app.post("/idp-token/{error}")
        def idp_token(error: str):  # an IdP token endpoint that answers with an OAuth error
            return JSONResponse({"error": error}, status_code=400)

    def add(self, **kw):
        e = entry(**kw)
        self.entries[e["client_id"]] = e
        return e


class Route(httpx.AsyncBaseTransport):
    def __init__(self, stub_app, fleet):
        self.stub = httpx.ASGITransport(app=stub_app)
        self.fleet_t = httpx.ASGITransport(app=fleet.app)
        self.fleet = fleet

    async def handle_async_request(self, request):
        if request.url.host != FLEET_HOST:
            return await self.stub.handle_async_request(request)
        self.fleet.calls += 1
        if self.fleet.down:
            raise httpx.ConnectError("connection refused", request=request)
        return await self.fleet_t.handle_async_request(request)


@pytest.fixture
def fleet():
    f = FakeFleet()
    f.add()
    f.add(cid=ID2, base=BASE_2, smb="corp-b", secret=SECRET_2)
    return f


@pytest.fixture
def clock(monkeypatch):
    now = [m.time.time()]
    monkeypatch.setattr(m.time, "time", lambda: now[0])
    return now


@pytest.fixture
def fp(proxy, monkeypatch, stub, fleet):
    """The proxy with Fleet's registry configured."""
    real = httpx._client.AsyncClient  # the class, not proxy's patched factory
    transport = Route(stub.app, fleet)
    monkeypatch.setattr(m.httpx, "AsyncClient", lambda **kw: real(transport=transport, **kw))
    monkeypatch.setattr(m, "FLEET_REGISTRY_URL", f"http://{FLEET_HOST}")
    monkeypatch.setattr(m, "FLEET_BROKER_TOKEN", BROKER_TOKEN)
    monkeypatch.setattr(c, "_registry_cache", {})
    return proxy


def fd_token(proxy, code, client=FD1, secret=SECRET_1, **over):
    return token(proxy, code, client, secret=secret, **over)


def location_q(r):
    return parse_qs(urlparse(r.headers["location"]).query)


# ---------------------------------------------------------------------------
# /authorize
# ---------------------------------------------------------------------------

class TestAuthorize:
    def test_active_entry_redirects_to_hosted_login(self, fp, store):
        r = authorize(fp, FD1)
        assert r.status_code == 302, r.text
        assert r.headers["location"].startswith(m.MONETA_HOSTED_UI_URL)
        (ttl, raw), = store.values()
        flow = json.loads(raw)
        assert flow["client_id"] == ID1
        assert flow["redirect_uri"] == FD1["redirect_uris"][0]
        assert flow["smb_id"] == "corp-a"
        assert flow["code_challenge"]

    def test_unknown_fd_client(self, fp, fleet, store):
        assert refused(authorize(fp, FD1, client_id=ID9))
        assert fleet.calls == 1 and store == {}

    def test_suspended(self, fp, fleet, store):
        fleet.add(state="suspended")
        assert refused(authorize(fp, FD1))
        assert store == {}

    @pytest.mark.parametrize("over", [
        {"state": "decommissioned"}, {"state": ""}, {"state": None},
        {"scheme": "ftp"}, {"scheme": "HTTPS"}, {"scheme": None},
        {"base_domain": None}, {"smb_id": None}, {"deployment_id": None},
    ])
    def test_values_off_the_contract_are_could_not_ask(self, fp, fleet, over):
        fleet.body = {**entry(), **over}
        assert schema_errors(fleet.body, "AuthClientOut")  # really off the contract
        r = authorize(fp, FD1)
        assert r.status_code == 503 and "location" not in r.headers

    def test_no_base_domain_is_a_404_and_refused(self, fp, fleet, caplog):
        caplog.set_level(logging.INFO)
        fleet.entries[ID1] = "no_base_domain"
        assert refused(authorize(fp, FD1))
        assert "reason=no_base_domain" in caplog.text
        fleet.add()  # a base domain filled in later works at once: not cached
        assert authorize(fp, FD1).status_code == 302

    @pytest.mark.parametrize("uri", [
        "https://evil.com/oauth2/callback",
        f"https://{BASE_1}/oauth2/callback",                    # the bare base
        f"https://plane.{BASE_1}/oauth2/callback",              # another label
        f"https://x.auth.{BASE_1}/oauth2/callback",             # deeper
        f"https://auth.{BASE_1}.evil.com/oauth2/callback",      # suffix trick
        f"https://auth.{BASE_2}/oauth2/callback",               # another deployment's
        f"http://auth.{BASE_1}/oauth2/callback",                # scheme mismatch
        f"https://auth.{BASE_1}:443/oauth2/callback",           # port
        f"https://u@auth.{BASE_1}/oauth2/callback",             # userinfo
        f"https://evil.com\\@auth.{BASE_1}/oauth2/callback",    # smuggled backslash
        f"https://evil.com\\.auth.{BASE_1}/oauth2/callback",
        f"https://auth%2e{BASE_1}/oauth2/callback",             # % in the authority
        f"https://evil.com%40auth.{BASE_1}/oauth2/callback",
        f"https://auth.{BASE_1}/oauth2/callback/",
        f"https://auth.{BASE_1}/oauth2/callback?rd=x",
        f"https://auth.{BASE_1}/other",
        f"https://AUTH.{BASE_1}/oauth2/callback",
    ])
    def test_redirect_uri_refused(self, fp, uri, store):
        assert refused(authorize(fp, FD1, redirect_uri=uri))
        assert store == {}

    def test_http_entry_accepts_http_only(self, fp, fleet):
        fleet.add(scheme="http")
        assert authorize(fp, FD1, redirect_uri=f"http://auth.{BASE_1}/oauth2/callback").status_code == 302
        assert refused(authorize(fp, FD1))  # https on an http deployment

    @pytest.mark.parametrize("base", [
        "evil.com/x", "a.example.net@evil.com", "a.example.net:8443", "a.example.net\\evil",
        "a%2eexample.net", "", "A.example.net", "-a.example.net", "a..example.net", "a.example.net.",
    ])
    def test_malformed_base_domain_refused(self, fp, fleet, base):
        fleet.add(base=base)
        assert refused(authorize(fp, FD1, redirect_uri=f"https://auth.{base}/oauth2/callback"))

    def test_static_client_never_sent_to_fleet(self, fp, fleet):
        fleet.entries["foss-portal-sandbox"] = entry(cid="foss-portal-sandbox")
        assert authorize(fp, PORTAL).status_code == 302
        assert fleet.calls == 0

    @pytest.mark.parametrize("cid", [
        "not-fd", "fd-", "fd-../../x", "fd-a/b", "fd-1111", ID1.upper(), ID1 + "0", ID1[:-1], ID1 + "\n",
    ])
    def test_non_fleet_ids_never_sent_to_fleet(self, fp, fleet, cid):
        assert refused(authorize(fp, FD1, client_id=cid))
        assert fleet.calls == 0

    def test_fleet_entry_for_another_client_id_is_not_trusted(self, fp, fleet):
        fleet.entries[ID1] = entry(cid=ID2, base=BASE_1)
        r = authorize(fp, FD1)
        assert r.status_code == 503 and "location" not in r.headers


# ---------------------------------------------------------------------------
# /mpass-callback: the corporate binding (Plan 3 §6)
# ---------------------------------------------------------------------------

class TestCallbackBinding:
    def test_own_smb_gets_a_code(self, fp, stub):
        r = sign_in(fp, stub, "alice", FD1)
        assert r.headers["location"].startswith(FD1["redirect_uris"][0] + "?")
        assert "code" in location_q(r)

    @pytest.mark.parametrize("user,reason", [("bob", "wrong_organization"), ("ivan", "not_corporate")])
    def test_other_users_access_denied(self, fp, stub, store, user, reason):
        q = location_q(sign_in(fp, stub, user, FD1))
        assert q["error"] == ["access_denied"] and q["error_description"] == [reason]
        assert "code" not in q
        assert not any(k.startswith("central_code:") for k in store)

    @pytest.mark.parametrize("smb", ["CORP-A", "corp-a ", " corp-a", "corp-"])
    def test_equality_is_verbatim(self, fp, fleet, stub, smb):
        fleet.add(smb=smb)
        assert location_q(sign_in(fp, stub, "alice", FD1))["error"] == ["access_denied"]

    @pytest.mark.parametrize("smb", [""])
    def test_entry_without_smb_fails_closed(self, fp, fleet, stub, store, smb):
        fleet.add(smb=smb)
        q = location_q(sign_in(fp, stub, "alice", FD1))
        assert q["error"] == ["access_denied"] and "code" not in q
        assert not any(k.startswith("central_code:") for k in store)

    def test_individual_user_with_no_corporate_id_on_unbound_entry_fails_closed(self, fp, fleet, stub):
        # ivan has no corporate_id claim; a missing binding must not equal a missing claim.
        fleet.add(smb="")
        assert location_q(sign_in(fp, stub, "ivan", FD1))["error"] == ["access_denied"]

    @pytest.mark.parametrize("smb", [""])
    def test_no_smb_does_not_match_an_empty_corporate_id(self, fp, fleet, stub, idp_sign, smb):
        # A corporate user whose corporate_id claim is "" must not match an
        # entry with no SMB: the binding fails closed, it is not an equality.
        fleet.add(smb=smb)
        cb = idp_login(stub, authorize(fp, FD1), "alice")
        q = {k: v[0] for k, v in parse_qs(cb.query).items()}
        for name in ("id_token", "access_token"):
            claims = jwt.decode(q[name], options={"verify_signature": False})
            q[name] = idp_sign({**claims, "custom:corporate_id": ""})
        r = fp.get(cb.path, params=q)
        assert location_q(r)["error"] == ["access_denied"]

    def test_suspended_mid_flow(self, fp, fleet, stub, store):
        r = authorize(fp, FD1)
        cb = idp_login(stub, r, "alice")
        fleet.add(state="suspended")
        c._registry_cache.clear()  # the 30 s cache has run out
        assert refused(fp.get(f"{cb.path}?{cb.query}"))
        assert not any(k.startswith("central_code:") for k in store)

    def test_decommissioned_mid_flow(self, fp, fleet, stub):
        r = authorize(fp, FD1)
        cb = idp_login(stub, r, "alice")
        del fleet.entries[ID1]
        c._registry_cache.clear()
        assert refused(fp.get(f"{cb.path}?{cb.query}"))

    def test_portal_keeps_its_own_rule(self, fp, stub):
        # The portal has no binding (smb_binding null): any user, corporate or not.
        for user in ("bob", "ivan"):
            assert "code" in location_q(sign_in(fp, stub, user, PORTAL))


# ---------------------------------------------------------------------------
# /token
# ---------------------------------------------------------------------------

class TestToken:
    @pytest.fixture
    def code(self, fp, stub):
        return code_of(sign_in(fp, stub, "alice", FD1))

    def test_right_secret(self, fp, code):
        r = fd_token(fp, code)
        assert r.status_code == 200, r.text
        claims = jwt.decode(r.json()["id_token"], proxy_key(fp), algorithms=["RS256"],
                            audience=ID1, issuer=ISSUER)
        assert claims["custom:corporate_id"] == "corp-a"

    @pytest.mark.parametrize("how", ["basic", "post"])
    def test_wrong_secret(self, fp, code, how):
        r = fd_token(fp, code, secret="wrong", how=how)
        assert r.status_code == 401 and r.json()["error"] == "invalid_client"

    def test_secret_of_another_deployment(self, fp, code):
        r = fd_token(fp, code, secret=SECRET_2)
        assert r.status_code == 401 and r.json()["error"] == "invalid_client"

    def test_code_of_x_redeemed_by_y(self, fp, code):
        r = fd_token(fp, code, FD2, secret=SECRET_2, redirect_uri=FD1["redirect_uris"][0])
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"

    def test_redirect_uri_must_match(self, fp, code):
        r = fd_token(fp, code, redirect_uri=FD2["redirect_uris"][0])
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"

    def test_suspended_client_cannot_redeem(self, fp, fleet, code):
        fleet.add(state="suspended")
        c._registry_cache.clear()
        r = fd_token(fp, code)
        assert r.status_code == 400 and r.json()["error"] == "unauthorized_client"

    def test_unknown_client(self, fp, fleet, code):
        del fleet.entries[ID1]
        c._registry_cache.clear()
        assert fd_token(fp, code).status_code == 401

    def test_rotation_list_of_two(self, fp, fleet, stub):
        fleet.entries[ID1]["secret_sha256"] = [_sha("old"), _sha(SECRET_1)]
        assert fd_token(fp, code_of(sign_in(fp, stub, "alice", FD1)), secret="old").status_code == 200

    def test_drift_a_bare_string_hash_is_could_not_ask(self, fp, fleet, stub):
        # The contract says a list. A bare string is drift: it fails the frozen
        # schema, and the proxy answers 503 rather than guess.
        code = code_of(sign_in(fp, stub, "alice", FD1))
        c._registry_cache.clear()
        fleet.body = {**entry(), "secret_sha256": _sha(SECRET_1)}
        assert schema_errors(fleet.body, "AuthClientOut")
        r = fd_token(fp, code)
        assert r.status_code == 503 and r.json()["error"] == "temporarily_unavailable"

    def test_fleet_down_uncached_is_503_not_401(self, fp, fleet, code):
        c._registry_cache.clear()
        fleet.down = True
        r = fd_token(fp, code)
        assert r.status_code == 503 and r.json()["error"] == "temporarily_unavailable"


class TestAudience:
    def test_token_from_x_refused_at_y(self, fp, stub):
        body = fd_token(fp, code_of(sign_in(fp, stub, "alice", FD1))).json()
        for tok in (body["id_token"], body["access_token"]):
            with pytest.raises(jwt.InvalidAudienceError):
                jwt.decode(tok, proxy_key(fp), algorithms=["RS256"], audience=ID2, issuer=ISSUER)
            assert jwt.decode(tok, proxy_key(fp), algorithms=["RS256"],
                              audience=ID1, issuer=ISSUER)["aud"] == ID1


# ---------------------------------------------------------------------------
# Caching (Plan 3 §4.3)
# ---------------------------------------------------------------------------

class TestCache:
    def test_positive_cached_30s(self, fp, fleet, clock):
        assert authorize(fp, FD1).status_code == 302
        clock[0] += 29
        assert authorize(fp, FD1).status_code == 302
        assert fleet.calls == 1
        clock[0] += 2
        assert authorize(fp, FD1).status_code == 302
        assert fleet.calls == 2

    def test_suspension_seen_after_30s(self, fp, fleet, clock):
        assert authorize(fp, FD1).status_code == 302
        fleet.add(state="suspended")
        clock[0] += 31
        assert refused(authorize(fp, FD1))

    def test_negative_not_cached(self, fp, fleet):
        del fleet.entries[ID1]
        assert refused(authorize(fp, FD1))
        fleet.add()
        assert authorize(fp, FD1).status_code == 302
        assert fleet.calls == 2

    @pytest.mark.parametrize("outage", ["down", 500, 502, 503, 401])
    def test_outage_serves_stale_up_to_10_min_then_503(self, fp, fleet, clock, caplog, outage):
        caplog.set_level(logging.INFO)
        assert authorize(fp, FD1).status_code == 302
        if outage == "down":
            fleet.down = True
        else:
            fleet.status = outage
        clock[0] += 9 * 60
        assert authorize(fp, FD1).status_code == 302
        assert "broker.registry_unavailable" in caplog.text
        clock[0] += 60 + 1
        r = authorize(fp, FD1)
        assert r.status_code == 503 and "location" not in r.headers

    def test_outage_for_a_never_seen_client_is_503_never_400(self, fp, fleet):
        fleet.down = True
        r = authorize(fp, FD1)
        assert r.status_code == 503 and "location" not in r.headers
        assert "unknown_client" not in r.text

    def test_stale_serving_does_not_renew_the_entry(self, fp, fleet, clock):
        assert authorize(fp, FD1).status_code == 302
        fleet.down = True
        clock[0] += 300
        assert authorize(fp, FD1).status_code == 302
        clock[0] += 301  # 601 s after the last real answer
        assert authorize(fp, FD1).status_code == 503

    def test_a_404_evicts_the_cached_positive(self, fp, fleet, clock):
        assert authorize(fp, FD1).status_code == 302
        del fleet.entries[ID1]
        clock[0] += 31
        assert refused(authorize(fp, FD1))
        fleet.down = True
        assert authorize(fp, FD1).status_code == 503  # not the old positive

    @pytest.mark.parametrize("body", [
        [], "x", {"client_id": ID1},
        {**entry(), "secret_sha256": ["not-hex"]},
        {**entry(), "secret_sha256": []},
        {**entry(), "secret_sha256": None},
        {**entry(), "secret_sha256": _sha("x")},
        {**entry(), "secret_sha256": [_sha("a"), _sha("b"), _sha("c")]},
        {**entry(), "secret_sha256": [_sha("a").upper()]},
    ])
    def test_malformed_answer_is_could_not_ask_and_not_cached(self, fp, fleet, body):
        assert schema_errors(body, "AuthClientOut")  # each one really is drift
        fleet.body = body
        r = authorize(fp, FD1)
        assert r.status_code == 503 and "location" not in r.headers
        assert c._registry_cache == {}

    def test_timeout_is_bounded(self):
        assert 0 < c.REGISTRY_TIMEOUT <= 5


# ---------------------------------------------------------------------------
# Per-bundle mode and config
# ---------------------------------------------------------------------------

class TestBundleModeNeverAsksFleet:
    def test_bundle_authorize_does_not_call_fleet(self, monkeypatch, store):
        calls = []
        monkeypatch.setattr(c, "_lookup", lambda *a: calls.append(a))
        assert m._CLIENTS == {}
        from fastapi.testclient import TestClient

        class Redis:
            async def setex(self, k, ttl, v):
                store[k] = v
        monkeypatch.setattr(m, "redis_client", Redis())
        r = TestClient(m.app, follow_redirects=False).get("/authorize", params={
            "client_id": ID1, "state": "s", "code_challenge": "x",
            "redirect_uri": "https://test-auth.example.com/oauth2/callback"})
        assert r.status_code == 302 and calls == []


class TestConfig:
    def _import(self, monkeypatch, tmp_path, **env):
        from tests.test_central import TestCentralConfig
        return TestCentralConfig()._import(monkeypatch, tmp_path, **env)

    def test_both_set_in_central_mode(self, monkeypatch, tmp_path):
        mod = self._import(monkeypatch, tmp_path, FLEET_REGISTRY_URL="http://fleet.svc:8000/",
                           FLEET_BROKER_TOKEN="t")
        assert mod.FLEET_REGISTRY_URL == "http://fleet.svc:8000"

    def test_neither_set_is_static_only(self, monkeypatch, tmp_path):
        assert self._import(monkeypatch, tmp_path).FLEET_REGISTRY_URL == ""

    @pytest.mark.parametrize("env", [
        {"FLEET_REGISTRY_URL": "http://fleet.svc:8000"},
        {"FLEET_BROKER_TOKEN": "t"},
        {"FLEET_REGISTRY_URL": "fleet.svc:8000", "FLEET_BROKER_TOKEN": "t"},
        # Per-bundle mode: a registry setting there would look enforced and is not.
        {"CLIENTS_FILE": None, "COOKIE_DOMAIN": ".example.com",
         "FLEET_REGISTRY_URL": "http://fleet.svc:8000", "FLEET_BROKER_TOKEN": "t"},
        {"CLIENTS_FILE": None, "COOKIE_DOMAIN": ".example.com", "FLEET_BROKER_TOKEN": "t"},
    ])
    def test_refuses_to_start(self, monkeypatch, tmp_path, env):
        with pytest.raises(RuntimeError):
            self._import(monkeypatch, tmp_path, **env)

    def test_control_bundle_mode_imports_without_them(self, monkeypatch, tmp_path):
        # The refusals above are the Fleet settings', not some other defect's.
        mod = self._import(monkeypatch, tmp_path, CLIENTS_FILE=None, COOKIE_DOMAIN=".example.com")
        assert mod._CLIENTS == {}


# ---------------------------------------------------------------------------
# Refresh (FOSS-611): an opaque handle bound to the client; the Cognito
# refresh token stays server-side. State and the corporate binding are
# re-checked on every refresh.
# ---------------------------------------------------------------------------

def rkey(handle):
    """Redis key of a refresh handle: keyed by its sha256 (the session id), so
    Redis never holds a handle a client could present."""
    return "central_refresh:" + _sha(handle)


def refresh(proxy, handle, client=FD1, secret=SECRET_1):
    return token(proxy, None, client, secret=secret, grant_type="refresh_token", refresh_token=handle,
                 code_verifier=None, redirect_uri=None)


class TestRefresh:
    @pytest.fixture
    def handle(self, fp, stub):
        body = fd_token(fp, code_of(sign_in(fp, stub, "alice", FD1))).json()
        return body["refresh_token"]

    def test_issues_an_opaque_handle_not_the_idp_token(self, fp, stub, store, handle):
        assert not handle.startswith("stub-refresh:") and len(handle) >= 32
        assert not any(handle in k for k in store)
        ttl, raw = store[rkey(handle)]
        assert ttl == c.CENTRAL_SESSION_MAX == 12 * 3600
        rec = json.loads(raw)
        assert rec["client_id"] == ID1 and rec["idp_refresh_token"] == "stub-refresh:alice"

    def test_refresh_reissues_for_this_client(self, fp, handle):
        r = refresh(fp, handle)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["refresh_token"] == handle
        assert "stub-refresh:" not in r.text
        claims = jwt.decode(body["id_token"], proxy_key(fp), algorithms=["RS256"], audience=ID1, issuer=ISSUER)
        assert claims["custom:corporate_id"] == "corp-a"
        jwt.decode(body["access_token"], proxy_key(fp), algorithms=["RS256"], audience=ID1, issuer=ISSUER)

    def test_replay_is_idempotent(self, fp, handle):
        # Not rotated: oauth2-proxy may refresh twice concurrently, and a
        # second delivery must not log the user out.
        assert refresh(fp, handle).status_code == 200
        assert refresh(fp, handle).status_code == 200

    def test_handle_of_x_refused_at_y(self, fp, handle):
        r = refresh(fp, handle, FD2, SECRET_2)
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"

    def test_wrong_secret(self, fp, handle):
        assert refresh(fp, handle, secret="wrong").status_code == 401

    @pytest.mark.parametrize("h", ["", "nope", "stub-refresh:alice"])
    def test_unknown_handle(self, fp, handle, h):
        r = refresh(fp, h)
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"

    def test_suspended(self, fp, fleet, handle):
        fleet.add(state="suspended")
        c._registry_cache.clear()
        r = refresh(fp, handle)
        assert r.status_code == 400 and r.json()["error"] == "unauthorized_client"

    def test_decommissioned(self, fp, fleet, handle):
        del fleet.entries[ID1]
        c._registry_cache.clear()
        assert refresh(fp, handle).status_code == 401

    def test_fleet_down_uncached_is_503(self, fp, fleet, handle):
        c._registry_cache.clear()
        fleet.down = True
        assert refresh(fp, handle).status_code == 503

    @pytest.mark.parametrize("smb", ["corp-b", ""])
    def test_corporate_binding_rechecked(self, fp, fleet, store, handle, smb):
        fleet.add(smb=smb)
        c._registry_cache.clear()
        r = refresh(fp, handle)
        assert r.status_code == 403 and r.json()["error"] == "access_denied"
        assert rkey(handle) not in store  # an answer, so the handle is burned

    def test_idp_refuses_burns_the_handle(self, fp, store, handle):
        ttl, raw = store[rkey(handle)]
        store[rkey(handle)] = (ttl, json.dumps({**json.loads(raw), "idp_refresh_token": "revoked"}))
        r = refresh(fp, handle)
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
        assert rkey(handle) not in store

    def test_idp_for_another_user_refused(self, fp, store, handle):
        ttl, raw = store[rkey(handle)]
        store[rkey(handle)] = (ttl, json.dumps({**json.loads(raw), "idp_refresh_token": "stub-refresh:adam"}))
        r = refresh(fp, handle)
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"

    def test_idp_unreachable_keeps_the_handle(self, fp, store, handle, monkeypatch):
        async def down():
            raise httpx.ConnectError("down")
        monkeypatch.setattr(m, "_get_token_endpoint", down)
        r = refresh(fp, handle)
        assert r.status_code == 503 and r.json()["error"] == "temporarily_unavailable"
        assert rkey(handle) in store  # could not ask is not no

    def test_static_client_refresh_keeps_its_rule(self, fp, stub):
        from tests.test_central import PORTAL_SECRET
        body = token(fp, code_of(sign_in(fp, stub, "ivan", PORTAL))).json()
        assert refresh(fp, body["refresh_token"], PORTAL, PORTAL_SECRET).status_code == 200

    def test_no_handle_or_idp_token_in_logs(self, fp, stub, caplog):
        caplog.set_level(logging.DEBUG)
        body = fd_token(fp, code_of(sign_in(fp, stub, "alice", FD1))).json()
        refresh(fp, body["refresh_token"])
        refresh(fp, body["refresh_token"], FD2, SECRET_2)
        assert body["refresh_token"] not in caplog.text and "stub-refresh:alice" not in caplog.text

    def test_discovery_offers_refresh(self, fp):
        assert "refresh_token" in fp.get("/.well-known/openid-configuration").json()["grant_types_supported"]

    @pytest.mark.parametrize("error", ["invalid_client", "unauthorized_client", "invalid_request"])
    def test_idp_refusing_us_not_the_user_keeps_the_handle(self, fp, store, handle, monkeypatch, error):
        # A wrong central client secret is our misconfiguration: it must not
        # burn every user's session. Only invalid_grant is about the token.
        async def endpoint():
            return f"http://{FLEET_HOST}/idp-token/{error}"
        monkeypatch.setattr(m, "_get_token_endpoint", endpoint)
        assert refresh(fp, handle).status_code == 503
        assert rkey(handle) in store



# ---------------------------------------------------------------------------
# The frozen contract (foss-fleet-provisioning contracts/FOSS-611.openapi.yaml
# at 9fc7f75, copied to tests/contracts/)
# ---------------------------------------------------------------------------

class TestContract:
    def test_fixtures_are_on_the_contract(self):
        for e in (entry(), entry(state="suspended", scheme="http", smb=""),
                  {**entry(), "secret_sha256": [_sha("a"), _sha("b")]}):
            assert not schema_errors(e, "AuthClientOut")
        for reason in ("unknown_client", "no_base_domain"):
            assert not schema_errors({"error": reason}, "AuthClientNotFound")

    def test_client_id_pattern_is_the_contracts(self):
        pattern = CONTRACT["components"]["schemas"]["AuthClientOut"]["properties"]["client_id"]["pattern"]
        assert pattern == "^" + c._FLEET_CLIENT_ID.pattern + "$"

    def test_every_valid_reply_is_accepted(self, fp, fleet):
        for e in (entry(), {**entry(), "secret_sha256": [_sha("a"), _sha(SECRET_1)]}, {**entry(), "extra": 1}):
            assert not schema_errors(e, "AuthClientOut")
            fleet.entries[ID1] = e
            c._registry_cache.clear()
            assert authorize(fp, FD1).status_code == 302

    @pytest.mark.parametrize("status", [401, 503, 500, 502])
    def test_declared_non_answers_are_could_not_ask(self, fp, fleet, status):
        fleet.status = status
        r = authorize(fp, FD1)
        assert r.status_code == 503 and "location" not in r.headers

    @pytest.mark.parametrize("body", [{"detail": "Not Found"}, {"error": "gone"}, "x"])
    def test_a_404_off_the_contract_is_could_not_ask(self, fp, fleet, body):
        # A wrong FLEET_REGISTRY_URL also answers 404; only the contract's 404 is "no".
        fleet.status_body = (404, body)
        r = authorize(fp, FD1)
        assert r.status_code == 503 and "location" not in r.headers


# ---------------------------------------------------------------------------
# /logout for Fleet clients. Acceptance criterion (FOSS-607 §3.3): clusters
# whitelist this service's host for oauth2-proxy's sign-out `rd`, which is safe
# only while post_logout_redirect_uri is an EXACT match against the registry.
# ---------------------------------------------------------------------------

class TestFleetLogout:
    TARGET = f"https://auth.{BASE_1}/"

    def logout(self, fp, client_id=ID1, target=TARGET):
        params = {"client_id": client_id, "post_logout_redirect_uri": target}
        return fp.get("/logout", params={k: v for k, v in params.items() if v is not None})

    def test_chains_through_the_one_logout_uri_and_back(self, fp, stub):
        r = self.logout(fp)
        assert r.status_code == 302
        idp = urlparse(r.headers["location"])
        q = parse_qs(idp.query)
        assert q["client_id"] == [m.OIDC_CLIENT_ID]
        assert q["logout_uri"] == [f"{ISSUER}/signed-out"]
        back = urlparse(stub.get(f"{idp.path}?{idp.query}", follow_redirects=False).headers["location"])
        r = fp.get(back.path)
        assert r.status_code == 302 and r.headers["location"] == self.TARGET

    def test_http_deployment(self, fp, fleet):
        fleet.add(scheme="http")
        assert self.logout(fp, target=f"http://auth.{BASE_1}/").status_code == 302
        assert refused(self.logout(fp))

    @pytest.mark.parametrize("target", [
        None, "",
        f"https://auth.{BASE_1}",                    # no slash
        f"https://auth.{BASE_1}/x",
        f"https://auth.{BASE_1}/?rd=https://evil.com",
        f"https://auth.{BASE_1}/#",
        f"https://auth.{BASE_1}:443/",
        f"http://auth.{BASE_1}/",
        f"https://{BASE_1}/",
        f"https://plane.{BASE_1}/",
        f"https://auth.{BASE_2}/",                   # another deployment's
        f"https://auth.{BASE_1}.evil.com/",
        f"https://evil.com\\@auth.{BASE_1}/",
        f"https://evil.com%40auth.{BASE_1}/",
        f"https://u@auth.{BASE_1}/",
        "https://evil.com/",
        f"{ISSUER}/",                                # this service itself
    ])
    def test_post_logout_uri_must_match_exactly(self, fp, target):
        assert refused(self.logout(fp, target=target))

    def test_unknown_client(self, fp):
        assert refused(self.logout(fp, client_id=ID9))

    def test_suspended_may_still_sign_out(self, fp, fleet):
        fleet.add(state="suspended")
        assert self.logout(fp).status_code == 302

    def test_fleet_down_uncached_is_503(self, fp, fleet):
        fleet.down = True
        r = self.logout(fp)
        assert r.status_code == 503 and "location" not in r.headers

    def test_signed_out_rechecks_against_the_registry(self, fp, fleet, stub):
        r = self.logout(fp)
        del fleet.entries[ID1]
        c._registry_cache.clear()
        r = fp.get("/signed-out")
        assert r.status_code == 200 and "location" not in r.headers

    def test_signed_out_refuses_a_forged_cookie(self, fp):
        import base64
        for target in ("https://evil.com/", f"https://auth.{BASE_2}/"):
            val = base64.urlsafe_b64encode(json.dumps({"client_id": ID1, "uri": target}).encode()).decode()
            fp.cookies.set("__Host-mpass_logout", val)
            assert "location" not in fp.get("/signed-out").headers

    def test_signed_out_with_fleet_down_does_not_redirect(self, fp, fleet):
        # The cookie is the browser's to forge; with no registry answer it is
        # never trusted for a redirect.
        assert self.logout(fp).status_code == 302
        c._registry_cache.clear()
        fleet.down = True
        r = fp.get("/signed-out")
        assert r.status_code == 200 and "location" not in r.headers



# ---------------------------------------------------------------------------
# Security review of #12, LOW-1: a session ends at sign-out, and at 12 h
# from sign-in whatever happens (absolute, never extended by a refresh).
# ---------------------------------------------------------------------------

class TestSessionEnd:
    @pytest.fixture
    def body(self, fp, stub):
        return fd_token(fp, code_of(sign_in(fp, stub, "alice", FD1))).json()

    def sid(self, fp, tok, aud=ID1):
        return jwt.decode(tok, proxy_key(fp), algorithms=["RS256"], audience=aud, issuer=ISSUER)["sid"]

    def test_tokens_carry_the_session_id(self, fp, body):
        sid = _sha(body["refresh_token"])
        assert self.sid(fp, body["id_token"]) == sid == self.sid(fp, body["access_token"])
        again = refresh(fp, body["refresh_token"]).json()
        assert self.sid(fp, again["id_token"]) == sid

    def age(self, store, handle, seconds):
        """Make the session `seconds` older. (Moving the clock instead would
        make the stub IdP mint tokens PyJWT, on the real clock, calls future.)"""
        ttl, raw = store[rkey(handle)]
        rec = json.loads(raw)
        store[rkey(handle)] = (ttl - seconds, json.dumps({**rec, "expires_at": rec["expires_at"] - seconds}))

    def test_session_is_12h_from_sign_in(self, fp, store, body):
        ttl, raw = store[rkey(body["refresh_token"])]
        assert ttl == 12 * 3600
        assert abs(json.loads(raw)["expires_at"] - (m.time.time() + 12 * 3600)) < 5

    def test_refresh_does_not_extend_the_session(self, fp, store, body):
        self.age(store, body["refresh_token"], 3600)
        assert refresh(fp, body["refresh_token"]).status_code == 200
        ttl, _ = store[rkey(body["refresh_token"])]
        assert 12 * 3600 - 3600 - 5 <= ttl <= 12 * 3600 - 3600

    def test_session_ends_12h_after_sign_in(self, fp, store, body):
        self.age(store, body["refresh_token"], 12 * 3600)  # still in the fake store: the check is ours
        r = refresh(fp, body["refresh_token"])
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
        assert rkey(body["refresh_token"]) not in store

    def test_just_before_12h_still_refreshes(self, fp, store, body):
        self.age(store, body["refresh_token"], 12 * 3600 - 30)
        assert refresh(fp, body["refresh_token"]).status_code == 200

    def logout(self, fp, hint, client_id=ID1):
        return fp.get("/logout", params={"client_id": client_id, "id_token_hint": hint,
                                         "post_logout_redirect_uri": f"https://auth.{BASE_1}/"})

    def test_logout_with_id_token_hint_ends_the_session(self, fp, store, body):
        assert self.logout(fp, body["id_token"]).status_code == 302
        assert rkey(body["refresh_token"]) not in store
        r = refresh(fp, body["refresh_token"])
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"

    def test_a_refreshed_id_token_also_ends_it(self, fp, store, body):
        again = refresh(fp, body["refresh_token"]).json()
        assert self.logout(fp, again["id_token"]).status_code == 302
        assert rkey(body["refresh_token"]) not in store

    def test_hint_for_another_client_does_not_end_it(self, fp, store, body):
        # fd-2222 cannot end fd-1111's sessions with fd-1111's token.
        r = fp.get("/logout", params={"client_id": ID2, "id_token_hint": body["id_token"],
                                      "post_logout_redirect_uri": f"https://auth.{BASE_2}/"})
        assert r.status_code == 302
        assert rkey(body["refresh_token"]) in store

    def test_forged_hint_does_not_end_it(self, fp, store, body, idp_sign):
        claims = jwt.decode(body["id_token"], options={"verify_signature": False})
        assert self.logout(fp, idp_sign(claims)).status_code == 302  # signed by someone else
        assert rkey(body["refresh_token"]) in store

    def test_expired_hint_still_ends_it(self, fp, store, body):
        # The 1 h id_token has usually expired by sign-out; it must still count.
        claims = jwt.decode(body["id_token"], options={"verify_signature": False})
        expired = c._sign({**claims, "iat": claims["iat"] - 7200, "exp": claims["iat"] - 3600})
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(expired, proxy_key(fp), algorithms=["RS256"], audience=ID1, issuer=ISSUER)
        assert self.logout(fp, expired).status_code == 302
        assert rkey(body["refresh_token"]) not in store

    def test_logout_without_hint_still_signs_out(self, fp, store, body):
        r = fp.get("/logout", params={"client_id": ID1, "post_logout_redirect_uri": f"https://auth.{BASE_1}/"})
        assert r.status_code == 302 and rkey(body["refresh_token"]) in store


class TestStaticIdsCannotShadowFleet:
    def test_static_fd_uuid_refused_at_load(self):
        with pytest.raises(RuntimeError):
            c._parse_clients({"clients": [{**PORTAL, "client_id": ID1}]})

    def test_static_fd_non_uuid_still_allowed(self):
        assert "fd-a" in c._parse_clients({"clients": [{**PORTAL, "client_id": "fd-a"}]})
