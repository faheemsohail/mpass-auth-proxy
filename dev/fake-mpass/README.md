# fake-mpass

A stand-in for mPass's hosted login and Cognito, so the whole sign-in flow of
`mpass-auth-proxy` can be built and tested without DevOps (FOSS-608, epic FOSS-607).

> **LOCAL AND SANDBOX ONLY.** It signs tokens with its own key for fixed test
> users and has no real accounts or secrets. Never trust its JWKS in production.
> It refuses to start unless `FAKE_MPASS_I_KNOW_THIS_IS_NOT_PRODUCTION=1` is set;
> put that in its environment so a mis-deploy fails loudly.

## What it imitates (all derived from `main.py`)

| Endpoint | `main.py` use |
|---|---|
| `GET /users/login?client_id&client_redirect_url` | `_moneta_login_url` (l.747). HTML picker of test users. |
| `GET /users/login/as?user&client_id&client_redirect_url` | Picker choice. 302 to `client_redirect_url?id_token&access_token&refresh_token`, the three params `_bridge_callback_impl` reads (l.857-859). No `state`. |
| `GET <issuer path>/.well-known/openid-configuration` | `_get_token_endpoint` (l.624); only `token_endpoint` is read. |
| `GET <issuer path>/.well-known/jwks.json` | `_get_jwks` (l.639), used to verify the id_token (l.880-897) and access_token (l.681-698). |
| `POST /oauth2/token` (`refresh_token` grant, form) | `_handle_refresh_token` (l.1013). Returns `access_token`, `id_token`, no new `refresh_token` (as Cognito). `client_secret` is ignored. |
| `GET /logout?client_id&logout_uri` | `OIDC_LOGOUT_URI` chain in `mpass_logout` (l.788-803). 302 to `logout_uri`. |

Not implemented because `main.py` does not call them: userinfo, authorize, revoke.

Claims: id_token has `iss`, `aud`=client_id, `sub`, `iat`, `exp`, `token_use=id`,
`cognito:username`, `email`, `custom:is_corporate`, `custom:corporate_id`. The
access_token has `iss`, `client_id`, `token_use=access`, `username`, `sub`, `iat`,
`exp` and the same two `custom:` claims. `custom:is_corporate` is the string
`"true"`/`"false"`, as `main.py` compares (l.718). Individual users carry no
`custom:corporate_id`.

## Test users (`users.json`)

| user | org |
|---|---|
| alice, adam | `corp-a` (SMB-A) |
| bob | `corp-b` (SMB-B) |
| ivan | individual: `custom:is_corporate=false`, no corporate_id |

Override with `FAKE_MPASS_USERS_FILE`. Entries: `username`, `email`, optional
`corporate_id`, optional `is_corporate` (default true when `corporate_id` is set).

## Configuration

| Env | |
|---|---|
| `FAKE_MPASS_I_KNOW_THIS_IS_NOT_PRODUCTION` | must be `1` or it will not start |
| `FAKE_MPASS_ISSUER_URL` | required; must equal the proxy's `OIDC_ISSUER_URL`. Its path is where discovery/JWKS are served, its origin is where `/oauth2/token` is advertised |
| `FAKE_MPASS_ALLOWED_REDIRECTS` | comma-separated URLs; `client_redirect_url` and `logout_uri` must match one by exact origin + path prefix (like Cognito's registered URLs). Unset = every login is a 400 and logout shows a page without redirecting. E.g. `https://auth.<domain>/mpass-callback,https://<domain>/` |
| `FAKE_MPASS_USERS_FILE` | optional, default `users.json` |
| `FAKE_MPASS_KEY_FILE` | optional PEM path: loaded if present, else generated and written there, so the kid survives restarts (created 0600, a group/world-readable existing file is refused). In the container `/app` is root-owned, so mount a writable volume for this path. Unset = new key each start |

## Run

```bash
pip install -r requirements.txt
export FAKE_MPASS_I_KNOW_THIS_IS_NOT_PRODUCTION=1 FAKE_MPASS_ISSUER_URL=http://127.0.0.1:9101/pool
export FAKE_MPASS_ALLOWED_REDIRECTS=http://127.0.0.1:8000/mpass-callback
uvicorn --factory fake_mpass:create_app --host 127.0.0.1 --port 9101 --no-access-log
```

Point the proxy at it: `OIDC_ISSUER_URL=http://127.0.0.1:9101/pool`,
`MONETA_HOSTED_UI_URL=http://127.0.0.1:9101`, `OIDC_LOGOUT_URI=http://127.0.0.1:9101/logout`.
Bind 127.0.0.1 on a high port locally; never 0.0.0.0:8000 or :4173 (CI runners share the machine).

## Tests

`tests/test_fake_mpass.py` (run with the repo suite) drives the real `main.py` against
the fake in-process: `/authorize`, fake login, `/mpass-callback`, `/token`, token
verification, the `SMB_CORPORATE_ID` check (bob and ivan refused when set to
`corp-a`), and refresh.

## Known limits

- It imitates what **our** code expects, not what mPass actually sends. FOSS-616
  (switch to real mPass) must verify against a real token sample.
- `main.py` reads `custom:is_corporate`/`custom:corporate_id` from the **access**
  token. Real Cognito access tokens do not normally carry custom attributes, so
  this may not hold for mPass; the fake puts them in both tokens.
- Refresh tokens are `fake-refresh:<user>`: stateless, never expire or rotate.
- `client_id`/`client_secret` are not checked; `aud` echoes whatever the caller sent.
- Tokens expire after 1 hour. No MFA, QR flow, or error pages of the real hosted UI.
- The synthetic `email` of real mPass users (`cognito:default_val`) is not imitated;
  the fake sends a plausible address.
- Discovery has no `authorization_endpoint` (the proxy never reads it). oauth2-proxy
  verifying against the fake's discovery, which it does when `LAUNCHPAD_EMAIL_CAPTURE`
  is off, will not find one; point it at the proxy's own discovery instead.
- `/logout` is tested directly and through `main.py`'s `/mpass/logout` redirect chain,
  but not through a real oauth2-proxy `sign_out`.
