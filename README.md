# mpass-auth-proxy

OIDC bridge that lets [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy)
sit in front of Moneta's mPass sign-in. Moneta issues tokens through an
implicit-grant QR flow; oauth2-proxy speaks OIDC authorization code + PKCE. This
service translates between the two so oauth2-proxy can own all session
management.

FastAPI + uvicorn, Redis/Valkey for short-lived bridge state.

> This service used to live at `mpass-auth-proxy/` inside
> [Pressingly/foss-server-bundle](https://github.com/Pressingly/foss-server-bundle).
> That copy is deprecated — this repository is the source of truth for all new
> development. Commit history up to the extraction stays in foss-server-bundle.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/authorize` | Receives the oauth2-proxy OIDC redirect, stores the request params (including the PKCE challenge), redirects the browser to the Moneta hosted UI |
| `GET`  | `/mpass-callback` | Moneta returns the `id_token` here; mints a one-time auth code and redirects to oauth2-proxy's `/oauth2/callback` |
| `POST` | `/token` | oauth2-proxy exchanges the auth code (or a refresh token) for real IdP tokens |
| `GET`  | `/mpass/login` | Redirects to `/oauth2/sign_in` — re-initiates SSO after a 401 |
| `GET`  | `/mpass/logout` | Clears the `mpass_bridge` cookie, then `302` to `/oauth2/sign_out`, optionally chaining through the IdP sign-out |
| `GET`  | `/health` | Liveness check |

### Traefik routing — cross-repo invariant

Every endpoint above **must** have a matching `Path()` entry in the `mpass-bridge`
Traefik router rule. A path missing from that rule falls through to the
oauth2-proxy catch-all, which answers with a `302` to the login page —
machine-to-machine callers (MCP OAuth token exchange) cannot follow a redirect,
so auth breaks silently rather than erroring.

The router rule does **not** live in this repository. It is the
`traefik.http.routers.mpass-bridge.rule` label on the `mpass-auth-proxy` service
in `docker-compose.yml` in `Pressingly/foss-server-bundle` (private), and it
currently lists exactly the six paths in the table above.

So adding, renaming or removing a route here is a **two-repo change**: land the
route in this repo, then open a coordinated PR against foss-server-bundle
updating the rule. The route is not reachable in any deployment until both have
shipped. If you do not have access to that repo, say so on your PR so someone who
does can pair the change.

## Configuration

All configuration is read from the environment at import time; the required
variables have no defaults and the process fails fast if they are missing. See
[`.env.example`](.env.example) for the full list with descriptions.

Required: `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `MONETA_HOSTED_UI_URL`,
`MPASS_CALLBACK_URL`, `REDIS_URL`, `COOKIE_DOMAIN`.

Optional: `OIDC_CLIENT_SECRET`, `SESSION_COOKIE_MAX_AGE_SECONDS`,
`OIDC_LOGOUT_URI`, `LOGOUT_REDIRECT_URL`, `SMB_CORPORATE_ID`, `PORTAL_URL`,
`LOG_LEVEL`.

Launchpad email capture (`LAUNCHPAD_EMAIL_CAPTURE`) adds its own required set:
the signing key (`MPASS_SIGNING_KEY_B64` or the `MPASS_SIGNING_KEY_GCP_*` pair),
`SYNTHETIC_EMAIL_DOMAIN` and `LAUNCHPAD_DB_PASSWORD`. The other `LAUNCHPAD_DB_*`
values default to the bundle's postgres. `.env.example` describes each one and
the order the key sources are tried in.

## Central mode (FOSS-609)

Opt-in. Set `CLIENTS_FILE` to a static-clients JSON file and this service
becomes one OIDC provider for many registered clients (Plan 3: one central
proxy per environment). With `CLIENTS_FILE` unset or empty, nothing below
applies and every route behaves as in the per-bundle mode described above.

**Configuration.** `CLIENTS_FILE` (see [`clients.example.json`](clients.example.json)),
plus, in addition to the required set above: `MPASS_PROXY_ISSUER_URL` (this
service's public `https://` origin, no trailing slash), `OIDC_LOGOUT_URI`, and a
signing key (`MPASS_SIGNING_KEY_B64` or the GCP pair; `MPASS_SIGNING_KEY_ALLOW_EPHEMERAL`
must be unset, because every replica must sign with one key). `COOKIE_DOMAIN` is not
needed, and `SMB_CORPORATE_ID` must be unset (each client's `smb_binding`
decides). Any defect in the clients file refuses startup. `MPASS_CALLBACK_URL`
is `<issuer>/mpass-callback`, and the Cognito client must allow
`<issuer>/signed-out` as a sign-out URL.

Each client entry has exactly these keys:

| Key | |
|---|---|
| `client_id` | unique |
| `secret_sha256` | list of lowercase hex `sha256(secret)`; two during a rotation. Generate each secret with `openssl rand -hex 32` and store `printf %s "$SECRET" \| sha256sum`. An unsalted sha256 is safe only for a high-entropy random secret: never register a hash of a chosen password. The hash cannot reveal the secret's length, so this is not checked at startup |
| `redirect_uris` | non-empty list, matched exactly |
| `post_logout_redirect_uris` | list (may be empty), matched exactly |
| `smb_binding` | `null` (no corporate check; e.g. the portal, which checks the claims itself) or the `custom:corporate_id` every user must carry |

A static `client_id` of Fleet's `fd-<uuid>` form refuses startup: static
clients are looked up first, so it would shadow the Fleet entry.

Every registered URI must pass the strict parse: absolute `http(s)`, ASCII, no
whitespace, no `\`, no fragment, no userinfo, no `%` in the authority, no dot
segments (also percent-encoded).

**Per-deployment clients from Fleet (FOSS-611).** Set `FLEET_REGISTRY_URL`
(Fleet's base URL) and `FLEET_BROKER_TOKEN` (a token that can only read the
registry route), both or neither; either one without `CLIENTS_FILE` refuses
startup. A `client_id` found in `CLIENTS_FILE` is never sent to Fleet. Ids
matching Fleet's pattern `fd-<lower-case uuid>` are looked up at
`GET <FLEET_REGISTRY_URL>/internal/auth/clients/{client_id}`; any other id is
unknown and never sent. The route's contract is foss-fleet-provisioning
`contracts/FOSS-611.openapi.yaml` (frozen at `9fc7f75`); a copy is in
`tests/contracts/`, and the tests validate every fake-Fleet reply against it,
so a contract change this proxy has not followed fails the build.

| Fleet answers | The proxy |
|---|---|
| 200 on the contract, `state: active` | caches it for 30 s per `client_id` |
| 200 on the contract, `state: suspended` | refuses `/authorize` (400, no redirect), the callback, and `/token` (`unauthorized_client`), refresh included |
| 404 `{"error": "unknown_client"}` or `{"error": "no_base_domain"}` | "no": 400, no redirect. Never cached, and it evicts a cached entry. The reason is logged, not branched on |
| anything else: unreachable, a timeout, 401, 503 (Fleet's broker token unset), other 5xx, a 404 without the contract's body (e.g. a wrong `FLEET_REGISTRY_URL`), or a 200 off the schema (a bare-string hash, three hashes, `null` fields, an unknown `state` or `scheme`) | "could not ask": serves the last real 200 for up to 10 min after Fleet gave it, then 503 "sign-in temporarily unavailable"; never 400 or `invalid_client`. Logs `broker.registry_unavailable`. One attempt per request, 3 s timeout |

A Fleet client's only redirect URI is `<scheme>://auth.<base_domain>/oauth2/callback`
(what Fleet sets as `OAUTH2_PROXY_REDIRECT_URL`), and its only
post-logout URI is `<scheme>://auth.<base_domain>/`; both are matched exactly,
after the strict parse. A `base_domain` that is not a plain lower-case DNS name
yields neither, so every request is refused. Its `smb_id` is the binding,
compared verbatim with `custom:corporate_id`; an empty `smb_id` admits no one.
`<app>-mcp.<base>` redirect hosts are not supported (FOSS-623, FOSS-624).

**Known cost: no negative cache.** A "no" is never cached, so a new
deployment can sign in at once, and every request naming a well-formed but
unknown `fd-<uuid>` costs one Fleet call. Bounding that is ingress rate
limiting in this service's deployment (FOSS-613), not code here.

**`/logout` is an exact match on purpose.** Each cluster's oauth2-proxy
whitelists this service's host so its sign-out can send the browser here
(FOSS-607 §3.3). That is safe only while `/logout` redirects nowhere but a
`post_logout_redirect_uri` equal to the registry's; a prefix or host match would
make every cluster an open redirect. `/signed-out` re-checks the cookie's
destination against the registry, and redirects nowhere if Fleet cannot be
asked. A suspended deployment may still sign out.

**Endpoints.** A refusal marked *400, no redirect* is a plain response with no
`Location`: the request is not trusted enough to choose a destination.

| Method, path | Parameters | Refusals |
|---|---|---|
| `GET /authorize` | `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method=S256`, optional `nonce` | 400, no redirect: unknown `client_id`; `redirect_uri` failing the strict parse or not byte-equal to a registered one; method absent (= `plain`) or not `S256`; challenge not 43 base64url chars; no `state`; `state` or `nonce` longer than 512 characters |
| `GET /mpass-callback` | from the IdP | 400 page, no redirect: no `__Host-mpass_flow` cookie, or the flow expired (600 s) or was used. 401: an id or access token failing verification, the two for different users, or either minted (`iat`) more than 60 s before the flow began (see "Login swap" below). 502: no access token, or the IdP JWKS unreachable. 503: Fleet could not be asked (see above). 400, no redirect: the client was deregistered or suspended mid-flow, or Fleet's answer no longer yields the flow's `redirect_uri` (its `scheme` or `base_domain` changed). A user outside the client's binding is redirected to the client's `redirect_uri` with `error=access_denied`, `error_description=not_corporate\|wrong_organization\|no_smb_binding` (the last: a Fleet entry with an empty `smb_id`) and `state` (RFC 6749 §4.1.2.1). Success: `redirect_uri?code=…&state=…` |
| `POST /token` | form: `grant_type=authorization_code`, `code`, `code_verifier`, `redirect_uri`, or `grant_type=refresh_token`, `refresh_token`; client auth by `client_secret_basic` **or** `client_secret_post` | 401 `invalid_client`: no, unknown or wrong credentials. 503 `temporarily_unavailable`: Fleet could not be asked (see above). 400 `unauthorized_client`: a Fleet client that is not active. 400 `invalid_request`: both auth methods. 400 `unsupported_grant_type`: anything else. 400 `invalid_grant`: unknown, used or expired (60 s) code; code issued to another client; `redirect_uri` not equal to the one at `/authorize`; a verifier outside RFC 7636's format, or one not matching the challenge. Client authentication runs first: a request with bad credentials leaves the code untouched, but once the client authenticates, the presented code is consumed even if the redemption is then refused |
| `GET /.well-known/openid-configuration` | | |
| `GET /.well-known/jwks.json` | | |
| `GET /logout` | browser form: `client_id`, `post_logout_redirect_uri`, optional `id_token_hint` (ends the refresh session, see "Refresh"). Backend form (oauth2-proxy's backend logout): only `id_token_hint`, always 204 | 400, no redirect: unknown client, or a URI not exactly in its `post_logout_redirect_uris`. 503: Fleet could not be asked. Success: 302 to the IdP sign-out, which returns to `/signed-out`, which re-checks and returns to the URI |
| `GET /signed-out` | `__Host-mpass_logout` cookie | without a valid cookie: a "signed out" page, no redirect |

`/token` success returns `id_token` and `access_token`, both RS256 JWTs signed
by this service (`kid` in the JWKS; header `typ` is `JWT` for the id_token and
`at+jwt` for the access token, RFC 9068, so a verifier can tell them apart) with `iss` = `MPASS_PROXY_ISSUER_URL`,
`aud` = the `client_id`, a 3600 s lifetime, `token_use` = `id` or `access`, and
the verified `sub`, `email`, `cognito:username`, `custom:is_corporate` and
`custom:corporate_id` (the last two from the verified Cognito access token;
absent if Cognito sent none), plus `nonce` in the id_token if one was sent.
`expires_in` is 3600. No Cognito token is returned.

**Refresh (FOSS-611).** When Cognito sent a refresh token, `/token` returns a
`refresh_token` that is an opaque handle. Redis `central_refresh:{sid}`, where
the session id `sid` is the handle's sha256, holds the client_id, the `sub`,
the Cognito refresh token and the session's absolute end; Redis never holds a
presentable handle. Every token issued for the session carries `sid`. A refresh
authenticates the client (which must be active), requires the handle to be
that client's, refreshes at Cognito with the central client (and
`OIDC_CLIENT_SECRET`), verifies both new tokens for the same `sub`, re-checks
the client's corporate binding, and returns newly signed tokens (`aud` = the
client) and the same handle.

| Answer | Handle |
|---|---|
| 400 `invalid_grant`: unknown handle, another client's handle, Cognito answers `invalid_grant`, or the tokens are for another user | deleted (except another client's: it stays its owner's) |
| 403 `access_denied`: the user fails the binding | deleted |
| 503 `temporarily_unavailable`: Cognito unreachable, any other Cognito error (e.g. `invalid_client`, our own misconfiguration), or an unverifiable reply | kept: "could not ask" is not "no" |

Why it is built this way:

- **No Cognito token leaves Moneta.** Clusters receive only tokens this service
  signed, and a handle that means nothing to Cognito.
- **The handle is bound to one client** because redeeming it needs that
  client's secret and the handle must be that client's. A handle stolen from
  deployment X is useless at Y, and useless at X without X's secret.
- **Not rotated.** oauth2-proxy can refresh one session concurrently, and a
  rotating handle would log the user out on the second delivery. A replayed
  refresh therefore succeeds.
- **12 h absolute.** A session ends 12 h after sign-in (`CENTRAL_SESSION_MAX`),
  whatever happens: a refresh keeps the remaining lifetime and never extends
  it, and a refresh past the end is `invalid_grant`.
- **Sign-out ends it.** `/logout?id_token_hint=<id_token>` deletes the session
  the token's `sid` names, so a copied session cookie cannot refresh after
  sign-out. The hint must be signed by this service for that `client_id`; an
  expired one still counts. A missing or bad hint is ignored and the sign-out
  proceeds.
- **The cluster's sign-out sends the hint server-side.** Each cluster sets
  `OAUTH2_PROXY_BACKEND_LOGOUT_URL=https://auth.<central>/logout?id_token_hint={id_token}`
  (FOSS-463). On sign-out, oauth2-proxy v7.15.5 makes a server-side GET to it
  with the session's id_token (outbound only, NAT-safe), accepts 200 or 204,
  and only logs any other answer; the sign-out proceeds either way. Its
  `http.Get` follows redirects. So `GET /logout` with neither `client_id` nor
  `post_logout_redirect_uri` is this backend form: the hint's audience must
  be a static or `fd-<uuid>` client, the session is deleted as above (no
  registry call, so this works while Fleet is down), and the answer is always
  **204, no redirect**, for any hint, valid or not, so it is no oracle.
- **The hint is never logged.** This service logs the `client_id` and `sub`,
  never the hint. uvicorn's access line prints the path with its query string;
  the Dockerfile's `--no-access-log` turns it off, and a filter on the
  `uvicorn.access` logger drops the query from every access line in case that
  flag is ever lost.
- **Accepted cost:** the handles live only in Redis (Valkey). Losing it ends
  every central session at its next refresh (oauth2-proxy refreshes every
  3000 s), and users sign in again.

**Login swap: a stopgap only.** The hosted login takes only `client_id` and
`client_redirect_url` and returns no `state` or `nonce`, so the IdP leg cannot be
bound to the browser's flow. A victim with an unfinished flow who follows an
attacker's captured `/mpass-callback?id_token=…&access_token=…` URL would be
signed in as the attacker. The proxy refuses Cognito tokens minted more than
`FLOW_TOKEN_SKEW` (60 s) before the flow began. The residual window is tokens
minted from 60 s before the victim's flow opens until it closes (up to 600 s). The real fix needs mPass
to round-trip `state` or a `nonce` (asked under FOSS-616).

**`GET /logout` has no CSRF protection**, as is usual for OIDC RP-initiated
logout: any page can sign a user out, but it can only send them to a registered
`post_logout_redirect_uri`. It takes no `id_token_hint` either, so it cannot
tell whether the request came from the signed-in user's client. Both are
acceptable for now; FOSS-611 did not change them.

`/mpass/login` and `/mpass/logout` answer 404 in central mode. The flow cookie
is `__Host-mpass_flow` (host-only, `Secure`, `HttpOnly`, `SameSite=Lax`), keyed
by an id this service generates, never by the caller's `state`. The launchpad
email overlay does not run in central mode.

The new routes are not in the bundle's `mpass-bridge` Traefik rule, and need not
be: the bundle does not run central mode, and they answer 404 there.

## Running locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # then fill it in
set -a && . ./.env && set +a
uvicorn main:app --host 0.0.0.0 --port 8000 --log-level info --no-access-log
```

`--no-access-log` is deliberate and is also baked into the Dockerfile: uvicorn's
per-request access lines echoed `/mpass-callback` query strings in full, which
carry the `id_token`, `access_token` and `refresh_token`. Application-level
events are logged through the module logger and remain visible.

## Tests

```bash
pip install -r requirements.txt -r requirements-test.txt
pytest
```

`pytest-dotenv` loads `tests/.env.test` before any test module is imported —
those are fake values, and they must stay in sync with the module-level
constants asserted in `tests/test_main.py`.

## Docker

```bash
docker build -t mpass-auth-proxy .
docker run --rm -p 8000:8000 --env-file .env mpass-auth-proxy
```

The container listens on port `8000` and runs as a non-root user.

## License

GPL-3.0 — see [LICENSE](LICENSE).
