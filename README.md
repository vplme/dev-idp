# dev-idp

A small OpenID Connect provider for local development. Apps redirect to it, you
click a user, and they get signed tokens carrying that user's claims. No
passwords, one YAML file, one binary.

> **Dev only.** dev-idp issues tokens to anyone who can reach it.

## Quick start

```sh
docker run --rm -p 127.0.0.1:5556:5556 ghcr.io/vplme/dev-idp
```

Point your app at it:

| Setting | Value |
| --- | --- |
| Issuer / discovery | `http://localhost:5556` |
| Client id | anything, such as `my-app` |
| Client secret | none, or anything (it isn't checked) |
| Redirect URI | any `localhost` URL |

Without a config file, dev-idp runs on [built-in defaults](src/defaults.yaml): any
client id with any localhost redirect URI is accepted, and the picker offers alice
(admin), bob (editor) and carol (viewer), each with a `roles` claim. Clients
without a registered secret must use PKCE (S256), which most OIDC libraries do by
default.

Log in from your app, pick a user, and you're in. `http://localhost:5556/` shows who
you're signed in as.

## Logging in

- The picker lists the client's users. Click one to log in. The optional
  **extra claims** field takes a JSON object that is added on top of the user's
  claims for that login only, such as `{"roles": ["viewer"]}`.
- The choice is remembered in a session cookie, so later logins skip the picker and
  `prompt=none` works. `prompt=login` always shows the picker. To switch user, use
  **Switch user** on `http://localhost:5556/`, or your app's logout.

## Your own users and clients

Create a `dev-idp.yaml` and mount its directory at `/config`. Mount the directory,
not the file: editors that save by renaming would otherwise break the mount and
hot-reload.

```sh
docker run --rm -p 127.0.0.1:5556:5556 -v "$PWD":/config:ro ghcr.io/vplme/dev-idp
```

```yaml
key_seed: my-project   # any string; the signing key is derived from it

users:
  - id: alice
    name: Alice Admin
    email: alice@example.com
    claims:
      roles: [admin]
      tenant: acme

clients:
  - id: my-app
    secret: dev                  # leave out for a browser app; it must then use PKCE
    redirect_uris:
      - http://localhost:3000/auth/callback
    post_logout_redirect_uris:   # optional, for logout
      - http://localhost:3000/
```

A config file replaces the built-in defaults entirely. Registered clients are checked
strictly: the secret must match and redirect URIs must match exactly. Add
`lenient: true` to also accept any other client id with any localhost redirect URI.

Edits to the YAML apply without a restart: clients, users, `lenient` and token TTLs.
`issuer`, `listen`, `key_seed` and `signing_key` need a restart. An invalid edit is
logged and the previous config stays active.

[`dev-idp.yaml`](dev-idp.yaml) is a commented example with every option.

## Configuration reference

- **clients**: each app's `id`, an optional `secret` (no secret = public client, which must
  use PKCE), `redirect_uris`, `post_logout_redirect_uris`, and optionally `users` (limits
  the picker), `audience` (replaces the default access token `aud` of `[client_id, issuer]`)
  and `scp: true` (also emit the scope as an array).
- **users**: `id` (becomes `sub`), `name`, `email`, optional `picture`, `given_name`,
  `family_name`, `preferred_username`, and free-form `claims` such as roles or tenant.
- **lenient: true** accepts any `client_id` and any localhost redirect URI, so a new
  project works without editing the config.

Which claims end up where:

| Claim | id_token | access token | userinfo |
| --- | --- | --- | --- |
| `name`, `given_name`, `family_name`, `preferred_username`, `picture` | with `profile` scope | – | with `profile` scope |
| `email`, `email_verified` | with `email` scope | – | with `email` scope |
| user `claims` and the picker's extra claims | yes | yes | yes |

`DEV_IDP_CONFIG` sets the config path (in the image, `/config/dev-idp.yaml`). These
override fields at startup:

| Variable | Field |
| --- | --- |
| `DEV_IDP_ISSUER` | `issuer` |
| `DEV_IDP_LISTEN` | `listen` |
| `DEV_IDP_KEY_SEED` | `key_seed` |
| `DEV_IDP_SIGNING_KEY` | `signing_key` |

### Signing key

The RS256 key is derived from `key_seed`, so the same seed gives the same key on
every machine and restart. The `kid` is the key's
[RFC 7638 thumbprint](https://www.rfc-editor.org/rfc/rfc7638): if a dependency
upgrade ever changes the derived key, clients see a new `kid`, fetch the JWKS
again, and you log in once more. To pin a key exactly, set `signing_key` to a PEM.

## Apps in Docker

The issuer must be one URL that both your browser and your app's backend can reach.
Inside a container, `localhost` is the container itself, so a backend there can't use
`http://localhost:5556`.

The simplest fix is a hostname that resolves on both sides:

1. Add `127.0.0.1 dev-idp` to `/etc/hosts`.
2. Run dev-idp as the `dev-idp` service on your apps' Docker network, with the
   issuer set to that hostname:

   ```yaml
   services:
     dev-idp:
       image: ghcr.io/vplme/dev-idp
       ports:
         - "127.0.0.1:5556:5556"
       volumes:
         - ./dev-idp:/config:ro   # directory holding dev-idp.yaml
       environment:
         DEV_IDP_ISSUER: http://dev-idp:5556
   ```

3. Configure your apps with the issuer `http://dev-idp:5556`.

One trade-off: with this setup, silent login (`prompt=none` in a hidden iframe)
stops working. `localhost:3000` and `localhost:5556` count as the same site, but
`localhost` and `dev-idp` don't, so browsers block dev-idp's session cookie in the
iframe. Redirect-based logins are unaffected.

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

## Developing dev-idp

```sh
cargo run --release                 # reads ./dev-idp.yaml, or the built-in defaults
cargo run --release -- --config path/to/dev-idp.yaml
docker compose up --build           # builds the image, mounts this directory
cargo test                          # unit tests plus end-to-end flow tests
cargo clippy --all-targets
```

[`sample-app/`](sample-app) is a small server-side Rust web app (axum and the
[`openidconnect`](https://crates.io/crates/openidconnect) crate) that logs in through
dev-idp: code flow with PKCE, nonce and state, then userinfo, refresh and logout. Its
home page shows the id_token, access token and userinfo claims, which is handy for
checking what a user's config produces. It's registered in `dev-idp.yaml` as the
`sample-app` client.

```sh
cd sample-app && cargo run                    # with dev-idp running on :5556
docker compose --profile sample up --build    # or both in Docker
```

Then open http://localhost:4000.
