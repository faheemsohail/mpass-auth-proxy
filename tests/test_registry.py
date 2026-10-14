"""Central mode, part 2 (FOSS-611): per-deployment clients from Fleet's registry.

Static clients (CLIENTS_FILE) are looked up first; `fd-` ids go to a fake Fleet
(`GET /internal/auth/clients/{client_id}`, Plan 3 §4.1), reached through the
same in-process transport as dev/stub-mpass-idp. Nothing binds a port.
"""
import json
import logging
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

import central as c
import main as m
from tests.test_central import (  # noqa: F401  (fixtures are used by name)
    ISSUER, PORTAL, _sha, allow, authorize, code_of, idp_login, proxy, proxy_key,
    refused, sign_in, store, stub, stub_key_file, token,
)

FLEET_HOST = "fleet.test"
BROKER_TOKEN = "broker-token-for-tests"
SECRET_1, SECRET_2 = "fd-1-secret-0123456789", "fd-2-secret-0123456789"
BASE_1, BASE_2 = "d1.foss.example.net", "d2.foss.example.net"
FD1 = {"client_id": "fd-1111", "redirect_uris": [f"https://auth.{BASE_1}/oauth2/callback"]}
FD2 = {"client_id": "fd-2222", "redirect_uris": [f"https://auth.{BASE_2}/oauth2/callback"]}


def entry(cid="fd-1111", smb="corp-a", base=BASE_1, scheme="https", state="active", secret=SECRET_1):
    return {"client_id": cid, "deployment_id": cid[3:], "smb_id": smb, "base_domain": base,
            "scheme": scheme, "state": state, "secret_sha256": [_sha(secret)]}


class FakeFleet:
    def __init__(self):
        self.entries: dict[str, dict] = {}
        self.calls = 0
        self.down = False          # connection refused
        self.status: int | None = None  # answer every lookup with this status
        self.body = None           # answer every lookup with this JSON body
        self.app = FastAPI()

        @self.app.get("/internal/auth/clients/{client_id}")
        def lookup(client_id: str, request: Request):
            if request.headers.get("authorization") != f"Bearer {BROKER_TOKEN}":
                return Response(status_code=401)
            if self.status:
                return Response(status_code=self.status)
            if self.body is not None:
                return JSONResponse(self.body)
            e = self.entries.get(client_id)
            return JSONResponse(e) if e else JSONResponse({"detail": "not found"}, status_code=404)

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
    f.add(cid="fd-2222", base=BASE_2, smb="corp-b", secret=SECRET_2)
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
        assert flow["client_id"] == "fd-1111"
        assert flow["redirect_uri"] == FD1["redirect_uris"][0]
        assert flow["smb_id"] == "corp-a"
        assert flow["code_challenge"]

    def test_unknown_fd_client(self, fp, fleet, store):
        assert refused(authorize(fp, FD1, client_id="fd-9999"))
        assert fleet.calls == 1 and store == {}

    def test_suspended(self, fp, fleet, store):
        fleet.add(state="suspended")
        assert refused(authorize(fp, FD1))
        assert store == {}

    @pytest.mark.parametrize("state", ["", "decommissioned", None])
    def test_any_state_but_active_refused(self, fp, fleet, state):
        fleet.entries["fd-1111"]["state"] = state
        assert refused(authorize(fp, FD1))

    def test_no_base_domain_refused(self, fp, fleet):
        fleet.add(base=None)
        assert refused(authorize(fp, FD1))

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

    @pytest.mark.parametrize("scheme", ["ftp", "HTTPS", "", None])
    def test_unknown_scheme_refused(self, fp, fleet, scheme):
        fleet.add(scheme=scheme)
        assert refused(authorize(fp, FD1))
        assert refused(authorize(fp, FD1, redirect_uri=f"{scheme}://auth.{BASE_1}/oauth2/callback"))

    def test_static_client_never_sent_to_fleet(self, fp, fleet):
        fleet.entries["foss-portal-sandbox"] = entry(cid="foss-portal-sandbox")
        assert authorize(fp, PORTAL).status_code == 302
        assert fleet.calls == 0

    @pytest.mark.parametrize("cid", ["not-fd", "fd-", "fd-../../x", "fd-a/b", "fd-" + "a" * 65])
    def test_non_fleet_ids_never_sent_to_fleet(self, fp, fleet, cid):
        assert refused(authorize(fp, FD1, client_id=cid))
        assert fleet.calls == 0

    def test_fleet_entry_for_another_client_id_is_not_trusted(self, fp, fleet):
        fleet.entries["fd-1111"] = entry(cid="fd-2222", base=BASE_1)
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

    @pytest.mark.parametrize("smb", [None, ""])
    def test_entry_without_smb_fails_closed(self, fp, fleet, stub, store, smb):
        fleet.add(smb=smb)
        q = location_q(sign_in(fp, stub, "alice", FD1))
        assert q["error"] == ["access_denied"] and "code" not in q
        assert not any(k.startswith("central_code:") for k in store)

    def test_individual_user_with_no_corporate_id_on_unbound_entry_fails_closed(self, fp, fleet, stub):
        # ivan has no corporate_id claim; a missing binding must not equal a missing claim.
        fleet.add(smb=None)
        assert location_q(sign_in(fp, stub, "ivan", FD1))["error"] == ["access_denied"]

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
        del fleet.entries["fd-1111"]
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
                            audience="fd-1111", issuer=ISSUER)
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
        del fleet.entries["fd-1111"]
        c._registry_cache.clear()
        assert fd_token(fp, code).status_code == 401

    def test_rotation_list_of_two(self, fp, fleet, stub):
        fleet.entries["fd-1111"]["secret_sha256"] = [_sha("old"), _sha(SECRET_1)]
        assert fd_token(fp, code_of(sign_in(fp, stub, "alice", FD1)), secret="old").status_code == 200

    def test_single_hash_as_a_string(self, fp, fleet, stub):
        # Fleet stores one hash (design 607 §4); a bare string is accepted too.
        fleet.entries["fd-1111"]["secret_sha256"] = _sha(SECRET_1)
        assert fd_token(fp, code_of(sign_in(fp, stub, "alice", FD1))).status_code == 200

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
                jwt.decode(tok, proxy_key(fp), algorithms=["RS256"], audience="fd-2222", issuer=ISSUER)
            assert jwt.decode(tok, proxy_key(fp), algorithms=["RS256"],
                              audience="fd-1111", issuer=ISSUER)["aud"] == "fd-1111"


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
        del fleet.entries["fd-1111"]
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
        del fleet.entries["fd-1111"]
        clock[0] += 31
        assert refused(authorize(fp, FD1))
        fleet.down = True
        assert authorize(fp, FD1).status_code == 503  # not the old positive

    @pytest.mark.parametrize("body", [
        [], "x", {"client_id": "fd-1111"},
        {**entry(), "secret_sha256": ["not-hex"]},
        {**entry(), "secret_sha256": []},
        {**entry(), "secret_sha256": None},
    ])
    def test_malformed_answer_is_could_not_ask_and_not_cached(self, fp, fleet, body):
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
            "client_id": "fd-1111", "state": "s", "code_challenge": "x",
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
