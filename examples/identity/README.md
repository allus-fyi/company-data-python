# Identity example — Python SDK

A thin, local demo backend that implements the shared **demo-backend contract
(v1)** and serves the SAME frontend bundle as every other allus SDK identity
example. It shows which `allus_company_data` call implements each identity
scenario: *Sign in with allme* (redirect + detached), one-time claims, connect
(stay-connected), OIDC login (via a real third-party OIDC client), and
standalone service-2FA + enrollment.

This is a **demo**, not a production service: disposable local state under
`.runtime/`, a single-worker stdlib server, and no hardening beyond ordinary
localhost developer use.

## Run it

```bash
git clone https://github.com/allus-fyi/company-data-python
cd company-data-python/examples/identity
python bin/start.py            # first run creates .venv + installs deps
# or a different port (only one example runs at a time — shared browser origin):
PORT=9000 python bin/start.py
```

Then open <http://localhost:8091>. The launcher:

1. wipes `.runtime/` (fresh state each boot),
2. creates a local `.venv` and installs this example's own deps
   (`requirements.txt`: the local SDK editable + [Authlib](https://authlib.org)),
3. fetches the pinned frontend release (`frontend.lock`), **verifies its
   sha256**, unpacks it to `.frontend/<tag>/`, and refuses a checksum or
   `contract.json` version mismatch,
4. serves the bundle + the contract API on one port.

## The eight scenarios → the SDK call that implements each

| # | Scenario | SDK / library call(s) |
|---|----------|-----------------------|
| 1 | Sign in — redirect | `OAuthClient.authorize_url('signin', …, response_mode='redirect')` → `OAuthClient.complete_sign_in` |
| 2 | Sign in — detached | `OAuthClient.authorize_url('signin', …, response_mode='detached')` → `OAuthClient.poll_result` → `complete_sign_in` |
| 3 | One-time claims | `OAuthClient.authorize_url('one_time', claims=…)` → `complete_sign_in` (decrypts with the app private key from config) |
| 4 | Connect (stay-connected) | `OAuthClient.authorize_url('connect', …)` → `complete_sign_in`, then `Client.connections` for the person's LIVE values |
| 5 | OIDC login | **Authlib** `OAuth2Session.create_authorization_url` → `fetch_token` → `jwt.decode` (id_token verify) |
| 6 | OIDC — continue on phone | same as 5 (completion via the phone-approved redirect leg) |
| 7 | 2FA at consent — **guide** card | no `/start`; a checklist linking to scenarios 1 & 5 |
| 8 | Standalone service-2FA + enrollment | `Client.two_factor.challenge` → `TwoFactorClient.wait_for_result`; `/enroll` → `OAuthClient.authorize_url('2fa_enroll', …)` (redirect + detached legs) |

## The config-file model

The browser POSTs a scenario's setup values to
`POST /api/scenarios/{id}/config`, which the backend writes to a **canonical SDK
config file** at `.runtime/config/{id}.json` (any PEM → `.runtime/config/keys/`
at `0600`, referenced by path). `/start` and `/enroll` then build the SDK OFF
that file via the role-appropriate constructor
(`OAuthClient.from_config` → `Config.from_idw_file`; `Client.from_config` →
`Config.from_file`) — you see the real SDK config the demo runs on. You never
hand-write it.

## Not part of the SDK package

Everything here is example-only. The published `allus-company-data` package is
defined by the SDK root `pyproject.toml`, which packages only `src/`; this
`examples/identity/` tree — and its Authlib dependency — is never distributed
with the SDK.
