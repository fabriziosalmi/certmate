# Single sign-on (OIDC)

CertMate supports authenticating users against an external OpenID Connect provider (Keycloak, Authentik, Okta, Google Workspace, Microsoft Entra, ...) using the Authorization Code + PKCE flow. SSO is **additive**: local username/password login and API keys keep working alongside it.

## Configuring an IdP

1. Open the CertMate UI as an admin → **Settings → SSO**.
2. Set the **Issuer URL** to the IdP's base URL (the path before `/.well-known/openid-configuration`). For example:
   - Keycloak: `https://idp.example.com/realms/main`
   - Authentik: `https://idp.example.com/application/o/certmate/`
   - Google: `https://accounts.google.com`
3. Fill in the **Client ID** and **Client Secret** issued by the IdP for the CertMate application.
4. In the IdP, register CertMate's callback URL as a valid redirect URI:

   ```
   https://your-certmate.example.com/api/auth/oidc/callback
   ```

5. Pick the claim names your IdP uses for username (`preferred_username` by default), email (`email`), and role (`groups`). Add **Role mappings** to translate IdP group/role claim values to CertMate roles — first match wins. Anything that doesn't match falls back to the configured **Default role** (`viewer` recommended).
6. Toggle **Enable OIDC/SSO** on and save. Visit `/login` in a new browser session to see the **Sign in with <Provider>** button.

## Role mapping example

For a Keycloak realm that exposes a `groups` claim, the configuration block in `settings.json` looks like:

```json
"oidc": {
  "enabled": true,
  "provider_name": "Keycloak",
  "issuer_url": "https://idp.example.com/realms/main",
  "client_id": "certmate",
  "client_secret": "********",
  "scopes": ["openid", "email", "profile", "groups"],
  "role_claim": "groups",
  "role_mappings": [
    { "claim_value": "certmate-admins",    "role": "admin" },
    { "claim_value": "certmate-operators", "role": "operator" }
  ],
  "default_role": "viewer",
  "auto_create_users": true,
  "link_by_email": true,
  "sync_role_on_login": true
}
```

## Provisioning and linking

- **Just-in-time provisioning** (`auto_create_users`) creates a CertMate user row on first login. The row has an empty password hash so JIT-provisioned SSO accounts cannot fall back to local login.
- **Email linking** (`link_by_email`) detects collisions with existing local users and merges identities — the user keeps **their existing password hash**, so a local-then-linked account can still log in either way during a rollout. Their role is preserved at the moment of linking, and from the *next* login onwards it is governed by `sync_role_on_login` like anyone else's (see below): with the default `true`, a linked local admin whose IdP groups map to `viewer` becomes a viewer on their second login. Disable `link_by_email` if you want JIT-only provisioning with no local-password fallback.
- Subject (`sub` + `iss`) lookup always wins over email matching, so an already-linked SSO user is never accidentally re-merged when their IdP email changes.
- **Role sync** (`sync_role_on_login`, default `true`) re-derives the role from the current claims on every login, so removing someone from an admin group in the IdP demotes them in CertMate too. Set it to `false` when the IdP only authenticates and roles are managed inside CertMate — an admin promoting someone by hand then survives their next login.
- A **disabled** CertMate user is refused at SSO login exactly as at local login: disabling an account locks it out regardless of how it authenticates.

## Security

- PKCE (S256) is enforced for every flow regardless of client type.
- The id_token's signature, audience, issuer, expiry and nonce are validated server-side by Authlib using the IdP's published JWKS.
- `client_secret` is masked (`********`) in every GET response and round-tripped safely through the Settings UI.
- The `oidc` settings block is on the bulk-POST reject list — only the dedicated `/api/auth/oidc/settings` endpoint can mutate it, with full audit.
- Failed callbacks count against the same per-IP rate limit as local login.
