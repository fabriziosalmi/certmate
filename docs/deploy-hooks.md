# Deploy Hooks

Closes [#117](https://github.com/fabriziosalmi/certmate/issues/117).

Deploy hooks are short shell commands CertMate runs **after** a certificate is issued, renewed, or revoked. Use them to reload services, push the new cert to a load balancer, post a notification, or anything else that needs to happen as a follow-up to a successful certbot run.

This guide walks through:

1. [What a hook is](#what-a-hook-is)
2. [Configuring hooks (UI + JSON)](#configuring-hooks)
3. [Environment variables passed to your command](#environment-variables-passed-to-your-command)
4. [Manual triggering](#manual-triggering)
5. [Security model: why some commands are rejected](#security-model)
6. [Common recipes](#common-recipes)
7. [Audit, history, and debugging](#audit-history-and-debugging)

---

## What a hook is

A hook is a JSON object with five fields:

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | yes | Stable identifier (UUID is fine; the UI auto-generates one). Used by `/api/deploy/test/<id>`. |
| `name` | string | yes | Human label shown in the UI and audit log. |
| `command` | string | yes | A single shell command (`sh -c`). Max 1024 chars. See [security](#security-model). |
| `enabled` | boolean | no | Defaults to `true`. Disabled hooks are skipped during automatic firing but can still be tested manually. |
| `timeout` | integer | no | Seconds. Default 30, capped at the system `MAX_TIMEOUT` (currently 300). |
| `on_events` | string array | no | Subset of `["created", "renewed", "revoked"]`. If absent, the hook runs on all three. |

Hooks live under two keys in `deploy_hooks`:

- **`global_hooks`** — fire for every domain. Good for "reload nginx after any cert changes".
- **`domain_hooks`** — keyed by exact domain name. Good for "push the LB cert for `api.example.com` to S3 after that specific cert renews".

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "global_hooks": [
      {
        "id": "5f8...",
        "name": "Reload nginx",
        "command": "/usr/sbin/nginx -s reload",
        "enabled": true,
        "timeout": 30,
        "on_events": ["created", "renewed"]
      }
    ],
    "domain_hooks": {
      "api.example.com": [
        {
          "id": "9b1...",
          "name": "Push to LB",
          "command": "/opt/scripts/push-cert-to-lb.sh",
          "enabled": true,
          "timeout": 120,
          "on_events": ["renewed"]
        }
      ]
    }
  }
}
```

If `enabled` at the top level is `false`, no hooks run on certificate events. Manual test runs (`POST /api/deploy/test/<id>`) still work — useful when iterating on a hook before flipping the master switch.

---

## Configuring hooks

### Via the UI

`Settings → Deploy Hooks`. Toggle the **Enabled** switch, then add Global or Per-Domain hooks. Each row has:

- name + command + timeout + event checkboxes
- a **Test** button (runs the hook against a synthetic domain `test.example.com` with `CERTMATE_EVENT=manual`)
- enable/disable toggle
- delete

Save settings to persist.

### Via API

```bash
# Read current config
curl -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/config

# Replace config (full document write — pass the whole deploy_hooks dict)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @hooks.json https://certmate.local/api/deploy/config
```

The POST replaces the whole `deploy_hooks` block; merge client-side if you want to preserve existing entries.

---

## Environment variables passed to your command

Every invocation sets these in the hook's process environment:

| Variable | Example value |
|---|---|
| `CERTMATE_DOMAIN` | `api.example.com` |
| `CERTMATE_CERT_PATH` | `/app/certificates/api.example.com/cert.pem` |
| `CERTMATE_KEY_PATH` | `/app/certificates/api.example.com/privkey.pem` |
| `CERTMATE_FULLCHAIN_PATH` | `/app/certificates/api.example.com/fullchain.pem` |
| `CERTMATE_EVENT` | `created` / `renewed` / `revoked` / `manual` |
| `CERTMATE_DRY_RUN` | Set to `1` only during dry-run; absent otherwise. |

Your command can reference these as `$CERTMATE_DOMAIN`, `"$CERTMATE_FULLCHAIN_PATH"`, etc. The values are passed by environment, not by string interpolation, so quoting works the same as in any normal shell.

The hook runs as the CertMate process user (in the Docker image: `certmate`, UID/GID 1000:1000) inside the container. Anything you `cp`, `curl`, `ssh`, etc. needs to be reachable from there.

---

## Manual triggering

Two ways to fire a hook outside the normal cert lifecycle:

### Per-hook test (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/test/<hook_id>
```

Runs only the hook with that `id`, against the synthetic domain `test.example.com`, with `CERTMATE_EVENT=manual`. Bypasses the `on_events` filter — useful for "does this command actually work?".

### Run all hooks for a domain (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/certificates/api.example.com/deploy
```

Fires every enabled global + domain-specific hook for `api.example.com` with `CERTMATE_EVENT=manual`, ignoring `on_events`. Returns a structured summary:

```jsonc
{
  "ok": true,
  "total": 3,
  "succeeded": 2,
  "failed": 1,
  "results": [
    {"hook_name": "Reload nginx", "exit_code": 0, "duration_ms": 142, ...},
    ...
  ]
}
```

This is what the **Run Deploy Hooks Now** button in the cert detail panel calls.

---

## Security model

Hooks are arbitrary code execution by design — that's the feature. To keep the blast radius bounded, the command field is validated **at save time and again at runtime** (defense in depth) and rejected if it contains:

### Blocked shell patterns

| Pattern | Reason |
|---|---|
| `` ` `` (backticks) | command substitution |
| `$(...)` | command substitution |
| `${...}` | parameter expansion (env var expansion is fine — only the `${...}` form is blocked) |
| `&&` / `\|\|` | logical chaining |
| `;` | statement separator |
| `\|` | pipe |
| `\r` / `\n` | newlines (so `sh -c` can't interpret them as `;`) |
| `> /` (redirect to absolute path) | prevents overwriting system files |
| `<<` | here-doc |
| `eval`, `source`, `. /` | shell builtins that load arbitrary code |

If you need any of those, put the logic in a script file inside the container and call the script directly:

```sh
/opt/scripts/deploy.sh
```

### Blocked file references

References to CertMate's own sensitive files are rejected outright (case-insensitive):

`settings.json`, `api_bearer_token`, `client_secret`, `vault_token`, `.env`, `private*key`, `.pem`

So `cat $CERTMATE_FULLCHAIN_PATH` is fine (the variable is expanded by the shell, the literal string `.pem` doesn't appear in `command`), but `cat /app/data/settings.json` would be rejected at save.

### What's allowed

- **Plain commands**: `/usr/sbin/nginx -s reload`, `systemctl reload haproxy`
- **Curl POSTs (webhooks)**: `curl -X POST -H "Content-Type: application/json" https://hooks.slack.com/...`
- **Variable expansion in arguments**: `curl -d "domain=$CERTMATE_DOMAIN" https://...`
- **JSON payloads with `$VAR` (no `${}`)**: `curl -d '{"domain":"$CERTMATE_DOMAIN"}' ...`
- **Single-script invocations**: `/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"`

If a command you used to be able to save now triggers `Command blocked at runtime: contains dangerous shell metacharacters`, see the version notes — the validator was tightened in v2.4.0 and slightly relaxed in v2.4.1+.

---

## Common recipes

### Reload nginx (global, all events)

```sh
/usr/sbin/nginx -t && /usr/sbin/nginx -s reload
```

(Note: `&&` is blocked. Wrap this in a script: `/opt/scripts/reload-nginx.sh`.)

### Reload haproxy

```sh
systemctl reload haproxy
```

### Push to a Slack webhook

```sh
curl -X POST -H 'Content-Type: application/json' -d "{\"text\":\"Cert renewed: $CERTMATE_DOMAIN\"}" https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Sync cert to a remote host

(Wrap in a script — no `;`, `&&` allowed inline.)

```sh
/opt/scripts/sync-cert.sh
```

Where `sync-cert.sh` is:

```sh
#!/bin/sh
set -eu
scp "$CERTMATE_FULLCHAIN_PATH" "$CERTMATE_KEY_PATH" deploy@lb:/etc/ssl/$CERTMATE_DOMAIN/
ssh deploy@lb 'systemctl reload haproxy'
```

### Skip hooks during dry-run

In your script:

```sh
[ -n "${CERTMATE_DRY_RUN:-}" ] && { echo "dry run, skipping"; exit 0; }
```

---

## Audit, history, and debugging

### Activity feed

`GET /api/deploy/history?limit=50` and the **Activity** UI tab show the last N hook runs with: hook name, domain, event, exit code, duration, stdout/stderr (truncated to 4096 bytes each), and timestamp.

### Debug console

Settings → Deploy Hooks has a debug console (toggle button bottom-right) that streams `loadConfig` / `saveConfig` / `testHook` events client-side. Useful when iterating on the UI.

### Audit log

Every hook run writes an `operation: deploy_hook` entry to the audit log with status `success`/`failure` plus the hook name, exit code, and duration. Visible via the Activity tab and `/api/audit`.

### Common failures

| Symptom | Likely cause |
|---|---|
| `Hook not found` | The hook ID in the test request doesn't match any hook in the saved config (UI was stale or the hook was just deleted). Refresh the page. |
| `Command blocked at runtime` | One of the [blocked patterns](#blocked-shell-patterns) made it past save. Move the offending logic into a script file. |
| `exit code 127` | Command not found inside the container (e.g. `nginx` isn't on `$PATH`). Use absolute paths or install the binary in the image. |
| `timeout after 30s` | Hook ran longer than its `timeout`. Bump it (max 300s) or move the work to a backgrounded script. |
| `Deploy hooks disabled` | `deploy_hooks.enabled` is `false`. Toggle the master switch in Settings. |
| `No hooks configured for <domain>` | Trying to run hooks for a domain with no global hooks AND no entry under `domain_hooks[<domain>]`. Add a hook (or call `/api/deploy/test/<id>` for a specific one). |

---

## See also

- [`modules/core/deployer.py`](../modules/core/deployer.py) — implementation
- [`modules/web/settings_routes.py`](../modules/web/settings_routes.py) — `/api/deploy/*` endpoints
- [`templates/partials/settings_deploy.html`](../templates/partials/settings_deploy.html) — UI partial
- [`static/js/settings-deploy.js`](../static/js/settings-deploy.js) — Alpine component
