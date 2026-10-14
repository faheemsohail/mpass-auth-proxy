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

Every registered URI must pass the strict parse: absolute `http(s)`, ASCII, no
whitespace, no `\`, no fragment, no userinfo, no `%` in the authority, no dot
segments (also percent-encoded).

**Endpoints.** A refusal marked *400, no redirect* is a plain response with no
`Location`: the request is not trusted enough to choose a destination.

| Method, path | Parameters | Refusals |
|---|---|---|
| `GET /authorize` | `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method=S256`, optional `nonce` | 400, no redirect: unknown `client_id`; `redirect_uri` failing the strict parse or not byte-equal to a registered one; method absent (= `plain`) or not `S256`; challenge not 43 base64url chars; no `state`; `state` or `nonce` longer than 512 characters |
| `GET /mpass-callback` | from the IdP | 400 page, no redirect: no `__Host-mpass_flow` cookie, or the flow expired (600 s) or was used. 401: an id or access token failing verification, the two for different users, or either minted (`iat`) more than 60 s before the flow began (see "Login swap" below). 502: no access token, or the IdP JWKS unreachable. A user outside the client's `smb_binding` is redirected to the client's `redirect_uri` with `error=access_denied`, `error_description=not_corporate\|wrong_organization` and `state` (RFC 6749 §4.1.2.1). Success: `redirect_uri?code=…&state=…` |
| `POST /token` | form: `grant_type=authorization_code`, `code`, `code_verifier`, `redirect_uri`; client auth by `client_secret_basic` **or** `client_secret_post` | 401 `invalid_client`: no, unknown or wrong credentials. 400 `invalid_request`: both auth methods. 400 `unsupported_grant_type`: anything but `authorization_code` (refresh is FOSS-611). 400 `invalid_grant`: unknown, used or expired (60 s) code; code issued to another client; `redirect_uri` not equal to the one at `/authorize`; a verifier outside RFC 7636's format, or one not matching the challenge. Client authentication runs first: a request with bad credentials leaves the code untouched, but once the client authenticates, the presented code is consumed even if the redemption is then refused |
| `GET /.well-known/openid-configuration` | | |
| `GET /.well-known/jwks.json` | | |
| `GET /logout` | `client_id`, `post_logout_redirect_uri` | 400, no redirect: unknown client, or a URI not exactly in its `post_logout_redirect_uris`. Success: 302 to the IdP sign-out, which returns to `/signed-out`, which re-checks and returns to the URI |
| `GET /signed-out` | `__Host-mpass_logout` cookie | without a valid cookie: a "signed out" page, no redirect |

`/token` success returns `id_token` and `access_token`, both RS256 JWTs signed
by this service (`kid` in the JWKS; header `typ` is `JWT` for the id_token and
`at+jwt` for the access token, RFC 9068, so a verifier can tell them apart) with `iss` = `MPASS_PROXY_ISSUER_URL`,
`aud` = the `client_id`, a 3600 s lifetime, `token_use` = `id` or `access`, and
the verified `sub`, `email`, `cognito:username`, `custom:is_corporate` and
`custom:corporate_id` (the last two from the verified Cognito access token;
absent if Cognito sent none), plus `nonce` in the id_token if one was sent. No
Cognito token is returned or stored. `expires_in` is 3600; there is no
`refresh_token`.

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
acceptable for now and are revisited in FOSS-611.

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
