# dev-idp

A small OpenID Connect provider for local development. Apps redirect to it, you
click a persona, and they get signed tokens carrying that persona's claims. No
passwords, one YAML file, one binary.

> **Dev only.** dev-idp issues tokens to anyone who can reach it. It listens on
> 127.0.0.1 by default; don't expose it.

## Run

```sh
cargo run --release                 # reads ./dev-idp.yaml
cargo run --release -- --config path/to/dev-idp.yaml
docker compose up --build           # uses ./dev-idp.yaml, port 5556
```

Then point your app at the issuer `http://localhost:5556`. Discovery is at
`http://localhost:5556/.well-known/openid-configuration`, and
`http://localhost:5556/` shows who you're signed in as.

## Configure

See [`dev-idp.yaml`](dev-idp.yaml) for a commented example. In short:

- **clients**: each app's `id`, an optional `secret` (no secret = public client, which must
  use PKCE), `redirect_uris`, `post_logout_redirect_uris`, and optionally `personas` (limits
  the picker), `audience` (replaces the default access token `aud` of `[client_id, issuer]`)
  and `scp: true` (also emit the scope as an array).
- **personas**: `id` (becomes `sub`), `name`, `email`, optional `picture`, `given_name`,
  `family_name`, `preferred_username`, and free-form `claims` such as roles or tenant.
- **lenient: true** accepts any `client_id` and any localhost redirect URI, so a new
  project works without editing the config.

| Claim | id_token | access token | userinfo |
| --- | --- | --- | --- |
| `name`, `given_name`, `family_name`, `preferred_username`, `picture` | with `profile` scope | – | with `profile` scope |
| `email`, `email_verified` | with `email` scope | – | with `email` scope |
| persona `claims` and the picker's extra claims | yes | yes | yes |

Edits to the YAML apply without a restart: clients, personas, `lenient` and token TTLs.
`issuer`, `listen`, `key_seed` and `signing_key` need a restart. An invalid edit is
logged and the previous config stays active.

`DEV_IDP_ISSUER`, `DEV_IDP_LISTEN`, `DEV_IDP_KEY_SEED` and `DEV_IDP_SIGNING_KEY`
override the matching fields at startup, and `DEV_IDP_CONFIG` sets the config path.

### Signing key

The RS256 key is derived from `key_seed`, so the same seed gives the same key on
every machine and restart. The `kid` is the key's
[RFC 7638 thumbprint](https://www.rfc-editor.org/rfc/rfc7638): if a dependency
upgrade ever changes the derived key, clients see a new `kid`, fetch the JWKS
again, and you log in once more. To pin a key exactly, set `signing_key` to a PEM.

## Logging in

- The picker lists the client's personas. Click one to log in. The optional
  **extra claims** field takes a JSON object that is added on top of the persona's
  claims for that login only, such as `{"roles": ["viewer"]}`.
- The choice is remembered in a session cookie, so later logins skip the picker and
  `prompt=none` works. `prompt=login` always shows the picker. To switch user, use
  **Switch user** on `http://localhost:5556/`, or your app's logout.

## Supported OIDC

| Endpoint | |
| --- | --- |
| `/.well-known/openid-configuration` | Discovery |
| `/jwks` | Public key |
| `/authorize` | Authorization code flow, PKCE (S256), `nonce`, `state`, `prompt` |
| `/token` | `authorization_code` and rotating `refresh_token` grants; `client_secret_basic`, `client_secret_post`, or `none` with PKCE |
| `/userinfo` | Claims for a bearer access token |
| `/logout` | RP-initiated logout with `post_logout_redirect_uri`, `state`, `id_token_hint` |

An issuer with a path, such as `http://localhost:5556/dex`, serves everything under
that path.

## Sample app

[`sample-app/`](sample-app) is a small server-side Rust web app (axum and the
[`openidconnect`](https://crates.io/crates/openidconnect) crate) that logs in through
dev-idp: code flow with PKCE, nonce and state, then userinfo, refresh and logout. Its
home page shows the id_token, access token and userinfo claims, which is handy for
checking what a persona's config produces. It's registered in `dev-idp.yaml` as the
`sample-app` client.

```sh
cd sample-app && cargo run                    # with dev-idp running on :5556
docker compose --profile sample up --build    # or both in Docker
```

Then open http://localhost:4000.

## Apps in Docker

The issuer must be one URL that both your browser and your app's backend can reach.
Inside a container, `localhost` is the container itself, so a backend there can't use
`http://localhost:5556`.

The simplest fix is a hostname that resolves on both sides:

1. Add `127.0.0.1 dev-idp` to `/etc/hosts`.
2. Run dev-idp with `DEV_IDP_ISSUER=http://dev-idp:5556`, on the same Docker
   network as your apps, under the service name `dev-idp`, with port 5556 published.
3. Configure your apps with the issuer `http://dev-idp:5556`.

One trade-off: with this setup, silent login (`prompt=none` in a hidden iframe)
stops working. `localhost:3000` and `localhost:5556` count as the same site, but
`localhost` and `dev-idp` don't, so browsers block dev-idp's session cookie in the
iframe. Redirect-based logins are unaffected.

## Develop

```sh
cargo test     # unit tests plus end-to-end flow tests
cargo clippy --all-targets
```
