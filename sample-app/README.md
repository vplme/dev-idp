# sample-app

An example server-side web app that logs in through dev-idp with the
[`openidconnect`](https://crates.io/crates/openidconnect) crate. Everything is in
[`src/main.rs`](src/main.rs):

- `/login` starts the authorization code flow with PKCE, `state` and `nonce`
  (`/login?prompt=login` always shows the persona picker).
- `/callback` checks `state`, exchanges the code, and verifies the id_token
  (signature, issuer, audience, nonce, `at_hash`).
- `/` shows the claims from the id_token, the access token and userinfo.
- `POST /refresh` uses the refresh token (it asks for `offline_access`).
- `POST /logout` clears the local session and does RP-initiated logout at dev-idp.

Sessions are kept in memory behind a cookie, so a restart logs you out.

```sh
cargo run    # dev-idp must be running on http://localhost:5556
```

Then open http://localhost:4000. Settings come from flags or environment variables:

| Variable | Default |
| --- | --- |
| `SAMPLE_ISSUER` | `http://localhost:5556` |
| `SAMPLE_CLIENT_ID` | `sample-app` |
| `SAMPLE_CLIENT_SECRET` | `dev` |
| `SAMPLE_URL` (callback is `<url>/callback`) | `http://localhost:4000` |
| `SAMPLE_LISTEN` | `127.0.0.1:4000` |
