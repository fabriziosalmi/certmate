# Deploy Hooks

Closes [#117](https://github.com/fabriziosalmi/certmate/issues/117).

Deploy hooks are short shell commands CertMate runs **after** a certificate is issued, renewed, or revoked. Use them to reload services, push the new cert to a load balancer, post a notification, or anything else that needs to happen as a follow-up to a successful certbot run.

> **On `revoked`.** Only client certificates can be revoked through CertMate — `POST /api/client-certs/<id>/revoke` — so that is when a `revoked` hook fires, with `CERTMATE_DOMAIN` set to the client certificate's identifier. There is no revoke operation for a server certificate, so no hook fires for one.

This guide walks through:

1. [What a hook is](#what-a-hook-is)
2. [Configuring hooks (UI + JSON)](#configuring-hooks)
3. [Environment variables passed to your command](#environment-variables-passed-to-your-command)
4. [Maintenance windows](#maintenance-windows)
5. [Manual triggering](#manual-triggering)
6. [Security model: why some commands are rejected](#security-model)
7. [Common recipes](#common-recipes)
8. [Audit, history, and debugging](#audit-history-and-debugging)

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
| `on_events` | string array | no | Subset of `["created", "renewed", "revoked"]`. If absent when the config is saved, it is set to `["created", "renewed"]` — `revoked` is opted into, so that adding a hook does not start running commands on revocations nobody wrote it for. A hook written into `settings.json` by hand is never normalised, so without `on_events` it fires on no certificate event at all; it still runs from a manual trigger. |
| `window` | object | no | A [maintenance window](#maintenance-windows). If absent, the hook runs as soon as the certificate is issued or renewed — the behaviour every hook has had until now. |

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
        "name": "Tell the load balancer",
        "command": "curl -fsS -X POST https://lb.internal/api/reload",
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

If `enabled` at the top level is `false`, no hooks run on certificate events. Per-hook test runs (`POST /api/deploy/test/<id>`) still work — useful when iterating on a hook before flipping the master switch. Running all hooks for a domain (`POST /api/certificates/<domain>/deploy`) does not: it refuses while the switch is off.

---

## Configuring hooks

### Via the UI

`Settings → Deploy Hooks`. Toggle the **Enabled** switch, then add Global or Per-Domain hooks. Each row has:

- name + command + timeout + event checkboxes
- a **Test** button (runs the hook against a synthetic domain `test.example.com` with `CERTMATE_EVENT=test` and `CERTMATE_DRY_RUN=1`)
- enable/disable toggle
- delete

Save settings to persist.

### Via API

```bash
# Read current config
curl -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/config

# Write config (top-level keys you send replace the stored ones)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @hooks.json https://certmate.local/api/deploy/config
```

The POST merges at the top level of `deploy_hooks`: each key you send (`enabled`, `global_hooks`, `domain_hooks`, `targets`) replaces the stored value whole, and a key you leave out is kept as it was. So sending `global_hooks` replaces the entire list; to add one hook, read the list, append, and send it back. An explicit empty list clears that key.

---

## Environment variables passed to your command

Every invocation sets these in the hook's process environment:

| Variable | Example value |
|---|---|
| `CERTMATE_DOMAIN` | `api.example.com` |
| `CERTMATE_CERT_PATH` | `/app/certificates/api.example.com/cert.pem` |
| `CERTMATE_KEY_PATH` | `/app/certificates/api.example.com/privkey.pem` — **not set** for a [CSR-only certificate](csr-only-certificates.md), whose key stays on the device |
| `CERTMATE_FULLCHAIN_PATH` | `/app/certificates/api.example.com/fullchain.pem` |
| `CERTMATE_CHAIN_PATH` | `/app/certificates/api.example.com/chain.pem` (intermediates only, no leaf — for targets that want the chain as a separate file) |
| `CERTMATE_TAGS` | `loadbalancer,env:prod` — the certificate's [tags](api.md), comma-separated and lower case; **empty** when it has none, and always set, so a hook can rely on it (since API contract 2.33) |
| `CERTMATE_EVENT` | `created` / `renewed` / `revoked` / `manual` (Deploy Now) / `test` (per-hook test) |
| `CERTMATE_DRY_RUN` | Set to `1` only for a per-hook test (`/api/deploy/test/<id>`, the **Test** button); absent otherwise, including for Deploy Now. The command still runs; this is only a signal your script can check. |

The paths are under CertMate's certificate directory: `/app/certificates` in the Docker image, or wherever `CERTMATE_CERT_DIR` points.

Your command can reference these as `$CERTMATE_DOMAIN`, `"$CERTMATE_FULLCHAIN_PATH"`, etc. The values are passed by environment, not by string interpolation, so quoting works the same as in any normal shell.

The hook runs as the CertMate process user (in the Docker image: `certmate`, UID/GID 1000:1000) inside the container. Anything you `cp`, `curl`, `ssh`, etc. needs to be reachable from there.

---

## Maintenance windows

Closes [#632](https://github.com/fabriziosalmi/certmate/issues/632).

A certificate renews when it is due, which is a time nobody chose: the renewal sweep runs at 02:00 with an hour of jitter, and only for the certificates inside the threshold that night. The hook then ran immediately. For a hook that restarts a database or reloads a load balancer, that is an outage at an unpredictable hour.

A `window` separates the two. The certificate still renews whenever it is due — that is driven by expiry and is not negotiable — but the **deploy** is held until the next time the window is open.

```jsonc
"window": {
  "start": "02:00",          // required, 24-hour HH:MM
  "end": "04:00",            // required, exclusive
  "days": ["sat", "sun"],    // optional; omit or leave empty for every day
  "timezone": "Europe/Rome"  // optional IANA name, defaults to UTC
}
```

The same field works on typed deploy targets, which is usually where you want it: a Kubernetes secret rollout is exactly the kind of deploy that belongs in a maintenance window.

### What the rules are

- **`end` is exclusive.** `02:00`–`04:00` and `04:00`–`06:00` are adjacent, not overlapping.
- **A window may cross midnight**, and belongs to the day it **starts** on. A `22:00`–`04:00` window on `["fri"]` is open at 02:00 on Saturday morning. Reading it the other way would silently require you to tick Saturday as well.
- **`start` and `end` may not be equal.** That reads equally well as "always open" and "never open", so it is refused rather than guessed. Use `00:00`–`23:59` for a whole day.
- **The timezone is an IANA name** (`Europe/Rome`, `America/New_York`), validated when you save. A typo is refused at that moment rather than silently holding every deploy for a window that never opens.
- **Daylight saving is handled by the zone, not by arithmetic.** On the spring-forward day a `02:00`–`04:00` Rome window opens at the local 03:00, because 02:00–02:59 does not happen; on the autumn day it is open across both passes of 02:00–02:59.

### What happens while a deploy is held

The queue lives at `data/pending_deploys.json` and survives a restart — the window is typically hours away.

- A second renewal before the window opens does **not** queue a second deploy. The hook reads the certificate from disk when it runs, so one deferred run always publishes the newest one.
- If the hook is deleted or disabled, or deploy hooks are switched off entirely, the queued deploy is **dropped** at the next drain. Your current configuration says not to run it.
- If you remove the window, the deploy is released at the next drain rather than waiting one more time.
- **Deploy Now consumes the deploy that was waiting.** If the hook (or typed target) you run by hand succeeds, its queued entry for that domain is removed: the certificate has been delivered, and running it again when the window opens would be an unannounced second deploy. If the manual run **fails**, the entry stays, so the window deploy is the retry. A renewal that happens *while* Deploy Now is running keeps its entry, because that certificate is newer than the one the manual run read. The two never run the same deploy at the same time: if the window opens while Deploy Now is running a hook, the scheduled run skips it and the next tick finds it either delivered or still owed, and if the scheduled run is already in the hook when you press the button, Deploy Now waits for it to finish and then runs. A queued deploy you do not want can still only be removed by disabling or deleting the hook (it is then dropped at the next drain).
- A hook that fails inside its window is **not** re-queued. It is recorded in the history like any other failure; re-queuing would retry every minute for as long as the window stayed open.
- A deploy still waiting after seven days is logged as a warning. That is not a limit — waiting is the feature — but a week means the window has not opened at all, which usually means the days or the timezone are not what you meant.

Deploys held for a window are invisible everywhere else: the certificate renewed, the history shows nothing, and nothing failed. `GET /api/deploy/pending` lists them with the window they are waiting for and when it next opens.

```bash
curl -H "Authorization: Bearer $TOKEN" https://certmate.local/api/deploy/pending
```

```json
[
  {
    "kind": "hook", "id": "6f0…", "domain": "api.example.com",
    "event": "renewed", "queued_at": "2026-09-08T13:12:04+00:00",
    "window": "02:00-04:00 Europe/Rome (sat, sun)",
    "next_run": "2026-09-12T00:00:00+00:00", "orphaned": false
  }
]
```

### What ignores the window

**Deploy Now** does. Pressing it is choosing this moment; holding the deploy until 02:00 would make the button do nothing visible. What it delivers is not delivered again: see *What happens while a deploy is held*. The same ignoring of the window is true of `POST /api/deploy/test/<id>`, which never touches the queue.

---

## Manual triggering

Two ways to fire a hook outside the normal cert lifecycle:

### Per-hook test (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/test/<hook_id>
```

Runs only the hook with that `id`, against the synthetic domain `test.example.com` (or the `domain` given in a JSON body), with `CERTMATE_EVENT=test` and `CERTMATE_DRY_RUN=1`. The command really runs. Bypasses the `on_events` filter, the hook's own `enabled` flag and the master switch — useful for "does this command actually work?".

### Run all hooks for a domain (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/certificates/api.example.com/deploy
```

Fires every enabled global + domain-specific hook (and every matching typed deploy target) for `api.example.com` with `CERTMATE_EVENT=manual`, ignoring `on_events`. Refused while the master switch is off. Returns a structured summary:

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

This is what the **Run deploy hooks now** button (play icon, Deployment section of the certificate detail panel) calls.

---

## Security model

Hooks are arbitrary code execution by design — that's the feature. To keep the blast radius bounded, the command field is validated **at save time and again at runtime** (defense in depth) and rejected if it contains:

### Blocked shell patterns

| Pattern | Reason |
|---|---|
| `` ` `` (backticks) | command substitution |
| `$(...)` | command substitution |
| `${...}` | parameter expansion. `$VAR` is fine, and so is `${CERTMATE_NAME}` with the closing brace right after the name; any other `${...}` form, including `${CERTMATE_DOMAIN:-x}`, is blocked |
| `&&` / `\|\|` | logical chaining |
| `;` | statement separator |
| `\r` / `\n` | newlines (so `sh -c` can't interpret them as `;`) |
| `> /` (redirect to absolute path) | prevents overwriting system files |
| `<<` | here-doc |
| `eval`, `source`, `.` (the source shorthand, with any argument) | shell builtins that load arbitrary code |

Two things that look like they belong on that list are allowed on purpose (#115): a simple pipe, for post-processing such as `curl ... | grep -q ok` (both sides must be a command the image carries — `jq` is not one of them), and a redirect to a relative path (`> out.txt`). Only a redirect to an absolute path is blocked.

If you need any of those, put the logic in a script file inside the container and call the script directly:

```sh
/opt/scripts/deploy.sh
```

### Blocked file references

A command that names one of CertMate's own sensitive files is rejected (case-insensitive):

`settings.json`, `api_bearer_token`, `client_secret`, `vault_token`, `.env`

Certificate files are not on the list: installing the certificate and its key (`privkey.pem`, `$CERTMATE_KEY_PATH`) is the normal job of a hook. `cat /app/data/settings.json` is rejected at save.

The check matches those names **as written**. It catches a hook that names one of those files by mistake. It does not stop a command that reaches the same file without spelling its name: a glob (`settings*`), a `?` wildcard, or a name split by quotes (`settings"."json`) all get past it. It is a guard against accidents, not a security boundary. Only an admin can save or run a hook, and an admin who can save a hook can already run any command as CertMate. The same holds for the shell patterns above.

### Sending the private key from a hook

A hook can send the key to a URL: `CERTMATE_KEY_PATH` is not on the blocked list
and `curl` is in the image, so `curl --data-binary @"$CERTMATE_KEY_PATH" …`
saves. CertMate does not look at what such a command does with the key. The
checks are yours to make:

- use `https://`, never `http://`: the key would cross the network in clear;
- do not add `-k`/`--insecure`, which turns off the check that the server is the
  one you meant;
- do not add `-L`/`--location`, which repeats the request, key included, at
  whatever address the answer names;
- do not let the command print what the server answers into the output: hook
  output is kept in the history, and the audit log cannot be edited.

For Kubernetes use the [typed target](#typed-deploy-targets) instead, which holds
to the first three for you.

### What's allowed

- **Plain commands**: `curl -fsS https://lb.internal/api/reload`, `openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -dates`
- **Curl POSTs (webhooks)**: `curl -X POST -H "Content-Type: application/json" https://hooks.slack.com/...`
- **Variable expansion in arguments**: `curl -d "domain=$CERTMATE_DOMAIN" https://...`
- **JSON payloads with `$VAR`**: `curl -H "Content-Type: application/json" -d "{\"domain\":\"$CERTMATE_DOMAIN\"}" ...`. The body has to be in double quotes: inside single quotes the shell never expands `$CERTMATE_DOMAIN`, and the receiver gets the literal text.
- **Single-script invocations**: `/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"`

If a command you used to be able to save now triggers `Command blocked at runtime: contains dangerous shell metacharacters`, see the version notes — the validator was tightened in v2.4.0 and slightly relaxed in v2.4.1+.

---

## Where a hook runs

**Inside the CertMate container**, as the process that issued the certificate —
not on the Docker host, and not on the machine you want to reload.

This is the single thing to get right before writing a hook, and the examples
in this page used to get it wrong. A command like `systemctl reload haproxy`
reads as if it reloads your load balancer. It does not: it runs in a container
that has no systemd, no haproxy and no nginx, and exits 127 — `not found` —
which is what [#856](https://github.com/fabriziosalmi/certmate/issues/856)
reported for `scp`.

What the published image actually contains, for a hook to use:

| | |
|---|---|
| **present** | `sh`, `bash`, `curl`, `openssl` |
| **not present** | `ssh`, `scp`, `sftp`, `rsync`, `jq`, `nginx`, `systemctl`, `haproxy`, and everything else |

That list is short on purpose. The runtime stage installs three packages, and
the Dockerfile explains why: every package added is surface that has to be
patched and scanned ([#403](https://github.com/fabriziosalmi/certmate/issues/403)).
It is not an oversight, so a hook has to work with what is there — or reach
something that has more.

`tests/test_a_hook_runs_where_certmate_runs.py` checks the examples below
against the image, so this table cannot drift from it again.

### Three ways to act on a machine that is not this one

**Ask it over the network.** Most things worth reloading have an API, and
`curl` is present. This is the pattern that works with no changes at all.

**Build your own image.** CertMate's image is a base like any other:

```
FROM fabriziosalmi/certmate:latest
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
USER certmate
```

Now `scp` is there, along with whatever else you added, and the surface is
yours to patch rather than everyone's.

**Mount a script and its dependencies.** A hook may call any path in the
container, so a bind-mounted script works — but it still runs in the
container, so anything it invokes has to be in there too.

---

## Common recipes

These run in the image as published. Each one is checked against it.

### Push to a Slack webhook

```sh
curl -X POST -H 'Content-Type: application/json' -d "{\"text\":\"Cert renewed: $CERTMATE_DOMAIN\"}" https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Tell something else the certificate changed

Anything with an HTTP API — a load balancer, a config management endpoint, your
own small agent beside the service:

```sh
curl -fsS -X POST -H "Authorization: Bearer $DEPLOY_TOKEN" --data-binary "@$CERTMATE_FULLCHAIN_PATH" https://lb.internal/api/certs/$CERTMATE_DOMAIN
```

`-f` matters: without it `curl` exits 0 on an HTTP error, and the hook reports
success for a deploy that did not happen.

### Check what was issued before shipping it

```sh
openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -subject -dates
```

### Run your own script

```sh
/opt/scripts/deploy.sh
```

Mounted into the container, and written against what the container has. Use a
script whenever you need `;` or `&&` — the command field rejects both, and the
script is where that logic belongs anyway.

### Act only on some certificates

Tag a certificate (`PATCH /api/certificates/<domain>` with `tags`, or **Edit** in
its detail panel) and one global hook can decide per certificate whether to
act. `CERTMATE_TAGS` is always set, comma-separated and lower case, and a tag
contains only letters, digits and `. _ - : /`, so it is safe to use unquoted. In
your script:

```sh
echo ",$CERTMATE_TAGS," | grep -q ',loadbalancer,' || exit 0
```

The surrounding commas are what make the match exact: without them `loadbalancer`
would also match a tag called `loadbalancer-old`.

### Skip real work during a Test run

In your script (the variable is set only by the per-hook **Test**):

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
| `Hook <id> is no longer in settings...` | The hook ID in the test request doesn't match any hook in the saved config: the page is stale, the hook was just deleted, or its command was rejected at save. Refresh the page. |
| `Command blocked at runtime` | One of the [blocked patterns](#blocked-shell-patterns) made it past save. Move the offending logic into a script file. |
| `exit code 127` | Command not found inside the container (e.g. `nginx` isn't on `$PATH`). Use absolute paths or install the binary in the image. |
| `timeout after 30s` | Hook ran longer than its `timeout`. Bump it (max 300s) or move the work to a backgrounded script. |
| `Deploy hooks are disabled. Enable them in Settings → Deploy.` | `deploy_hooks.enabled` is `false` and you ran all hooks for a domain. Toggle the master switch in Settings. |
| `No enabled hooks or deploy targets configured for <domain>...` | Trying to run hooks for a domain with no enabled global hook, no enabled entry under `domain_hooks[<domain>]` and no typed target for it. Add a hook (or call `/api/deploy/test/<id>` for a specific one). |

---

## Typed deploy targets

A **typed deploy target** is a declarative alternative to a shell hook for a
common destination, so you don't hand-roll `kubectl` + credentials. Targets live
under `deploy_hooks.targets` and fire from the same lifecycle points as hooks
(issuance + every renewal, and manual deploy), with the same failure isolation —
a target that fails logs, audits, and raises the `deploy_hook_failed` alert, but
never blocks the certificate operation.

The first typed target is **Kubernetes Secret**: it writes the renewed
`fullchain.pem` / `privkey.pem` into a `kubernetes.io/tls` Secret via
Server-Side Apply (one idempotent create-or-update).

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "targets": [
      {
        "id": "prod-web-tls",
        "name": "Publish to prod web Secret",
        "type": "kubernetes-secret",
        "enabled": true,
        "on_events": ["created", "renewed"],
        "domains": ["example.com"],          // empty/omitted = all managed domains
        "config": {
          "secret_name": "example-tls",
          "namespace": "web",
          // Option A — talk to the API server directly:
          "api_server": "https://10.0.0.1:6443",
          "token": "<service-account bearer token>",
          "ca_cert": "-----BEGIN CERTIFICATE-----\n…",  // optional; else system CAs
          "verify_ssl": true
          // Option B — running inside the cluster: set "in_cluster": true instead,
          // and the API server, token, CA and default namespace are read from the
          // mounted service account.
        }
      }
    ]
  }
}
```

Configure it via `POST /api/deploy/config` (the same admin-only endpoint as
shell hooks). The service-account token used should be scoped to
`patch`/`create` on Secrets in the target namespace.

> **Security:** the deploy config is admin-only, and — like a secret embedded in
> a shell hook — the Kubernetes `token` is stored in settings and returned to
> admins on `GET /api/deploy/config`. Keep the token minimally scoped.

A target sends the private key to the address it is configured with, so two
things are held to:

- **Redirects are not followed.** A redirect would repeat the request, key
  included, at whatever address the answer names. A `3xx` from the API server is
  reported as a failure that says so (without the address it named); point
  `api_server` at the address that answers directly.
- **What comes back is never copied into the records.** The answer to a failed
  request is shown to the operator, and also lands in the audit log, the deploy
  history and the failure alert. The audit log is a hash chain and cannot be
  edited afterwards, so the answer is stripped of the bearer token and of the key
  (as PEM, JSON-escaped, base64, URL-encoded, or a line of it) before it is
  shortened and kept.

`verify_ssl: false` is still accepted for a cluster with a certificate you cannot
verify. It turns off the check that the server is the one you configured, so use
it only on a network you control.

### Webhook target: deliver the certificate, and optionally the key

A **notification webhook** (Settings → Notifications) *announces* a renewal, and
what it reports reaches alerts, mail and logs. It never carries the private key
([webhooks.md](webhooks.md)). The **webhook target** *delivers*: it sends the
certificate and chain, and, if the template asks for it, the private key, to a
HTTPS endpoint you chose, typically an appliance or a service with an upload
API. They are different things with different rules, so this is a deploy target
and not another placeholder of the notification webhook.

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "targets": [
      {
        "id": "lb-cert",
        "name": "Upload to the load balancer",
        "type": "webhook",
        "enabled": true,
        "domains": ["shop.example.com"],      // required: never "all domains" by default
        "on_events": ["created", "renewed"],
        "config": {
          "url": "https://lb.internal:8443/api/certificate",
          "method": "POST",                   // POST, PUT or PATCH
          "payload_template": "{\"name\": \"{{domain}}\", \"cert\": \"{{fullchain}}\", \"key\": \"{{privkey_pkcs8}}\"}",
          "auth_type": "bearer", "auth_token": "<token>",   // none | bearer | basic | header
          "ca_cert": "-----BEGIN CERTIFICATE-----\n…",     // or "pin_sha256": "<fingerprint>"
          "allow_internal": true,             // the destination is on a private network
          "acknowledge_key_delivery_to": "lb.internal"      // needed because the template names the key
        }
      }
    ]
  }
}
```

**In the UI.** Settings → Deploy → **Deploy Targets** lists every target and
edits the webhook ones: name, domains (required), events, URL, method,
authentication, signing secret, how the server is verified, a private-network
switch, timeout and attempts, and the payload with the variables as buttons. The
key variables are red, and adding one is what triggers the confirmation below. **Preview what would be
sent** calls the preview endpoint below and shows the destination with its port,
how the server is verified, the files a delivery reads, the headers (credentials
masked) and the body rendered with an example certificate and key. A preview
disappears as soon as the form changes, so what is on screen is always what would
be saved.

If the payload names a private-key variable, the form shows a red box with the
destination host and keeps **Save target** disabled until you have typed that host.
A target already confirmed for its host is not asked again when you rename it or
change its domains; a different host asks again and says which host it was
confirmed for. Saving writes only `targets`, from the list the server holds at that
moment with this one target changed, so it cannot overwrite an edit made through
the API in between, and it leaves the other target types (Kubernetes secrets)
exactly as they are. They are listed there and edited through the API. The page
never sends a consent: the server writes it.

**Template variables.** The payload is JSON you write. A placeholder inside a
string is inserted escaped, so a PEM (which has newlines) cannot break the JSON.

| Variable | What it is |
|---|---|
| `{{cert}}`, `{{fullchain}}`, `{{chain}}` | the certificate, the certificate with its chain, the chain alone (PEM) |
| `{{privkey_pkcs8}}` | the private key as PKCS#8 (`BEGIN PRIVATE KEY`) |
| `{{privkey_traditional}}` | the private key as PKCS#1 for RSA (`BEGIN RSA PRIVATE KEY`) or SEC1 for EC (`BEGIN EC PRIVATE KEY`). A key type with no such form, such as Ed25519, is refused with a message, not silently replaced |
| `{{event}}`, `{{domain}}`, `{{timestamp}}`, `{{certificate_sha256}}` | the event, the certificate's name, the time, and the SHA-256 of the leaf certificate |

There is no bare `privkey`: the two spellings make the choice visible, and a
typo in a name is refused when you save instead of silently sending nothing. A
name that is not in this table is refused.

**Sending the key is a decision about a destination.** If the template names a
private-key variable, the save must carry `config.acknowledge_key_delivery_to`
set to the host in `url`. The server then records who confirmed it and when
(`delivery_consent`, returned by `GET /api/deploy/config`); it is never read from
what you send. If you later change the host, the confirmation no longer applies:
the target refuses to send until it is given again, and a save without it is
refused. Each confirmation is in the audit log.

**How the server is verified.** Always. By default against the system store. With
`ca_cert`, against that CA only (it replaces the system store). With
`pin_sha256`, against the exact SHA-256 fingerprint of the server's own
certificate, for an appliance that signs itself: give the fingerprint (colons
allowed), not the certificate. There is no setting that turns verification off,
and the URL must be `https://`.

**Where it may send.** The host is resolved once, every address is checked, and
the connection goes to that address. A loopback, link-local or cloud-metadata
address is never a destination. A destination on a private network needs
`allow_internal: true` **on this target**, which is deliberate and narrower than
a switch for the whole instance. Redirects are not followed: a `3xx` is a
failure that says so.

**What it does when something goes wrong.** An error from the network, or a
status of `408`, `425`, `429`, `500`, `502`, `503` or `504`, is retried with backoff
up to `attempts` (default 3, at most 5). Any other status is not: a `4xx` says the
request is wrong, and sending a key again to be told so again helps nobody. Every delivery carries an `Idempotency-Key`
that is the same for the retries of one delivery and for the same certificate
sent again, and different for the next certificate, so a receiver can tell a
repeat from a new one. With `signing_secret` the body is signed in
`X-CertMate-Signature`, as for the notification webhook.

**What is recorded, and what is not.** A result is a status and one sentence that
names the host: never the address, the query, the headers, the body you sent or
the body the receiver answered, which can echo what it was sent. A delivery that
carried the private key is marked in the audit log: where it went (`key_sent_to`),
for which domain, the certificate's fingerprint, the status and the attempts, and
never the key. A reset after the TLS handshake is recorded as possibly sent,
because it cannot be told apart from one before it.

**There is no "send a test" for a target that sends the key**, on purpose. A test
that delivered a key to an appliance that accepts uploads would install it in
place of the real one. Use the **preview** instead
([`POST /api/deploy/targets/preview`](api.md)): it renders the request against an
example certificate and key, reads no file and sends nothing. To deliver for real
once, use *Run hooks for a domain* (admin), which is an explicit action.

**What this protects against, and what it does not.**

| It protects against | It does not |
|---|---|
| The key going to a host you did not confirm, including after the URL is edited | A receiver that is compromised or that logs what it is sent: it holds the key once it has it. Some automation platforms keep every request body in an execution history; do not point a key-carrying target at one |
| A redirect, a rebound DNS answer or a metadata address taking the request elsewhere | An administrator: anyone who can save this configuration can already write a [shell hook](#sending-the-private-key-from-a-hook) that sends the key, without any of the checks above |
| Sending over plain HTTP, or to a server nobody verified | Keeping the key out of the receiver's own backups and logs |
| The receiver's answer carrying the key into the audit log | |
| | The target's own credentials: `auth_token`, `auth_password` and `signing_secret` are kept in `settings.json` (mode `0600`) and returned to an administrator by `GET /api/deploy/config`, exactly as a Kubernetes target's token is. The form shows them as password fields. Give the receiver a token that can do this one thing |

Not in this version: a bundle as a file upload or PKCS#12, and custom request
headers other than the authentication one. Say what a receiver needs.

#### Receiving it in n8n

Checked against n8n 2.41.4 with a real certificate, a Webhook node and the payload
below; the three steps are what had to be done, not what is generally true of n8n.

```json
{"domain": "{{domain}}", "event": "{{event}}",
 "certificates": {"cert": "{{cert}}", "key": "{{privkey_pkcs8}}", "rsa_key": "{{privkey_traditional}}",
                  "fullchain": "{{fullchain}}", "intermediate": "{{chain}}"}}
```

1. **n8n has to answer over HTTPS.** A default n8n listens on plain HTTP, and a target
   refuses that (`url must be https://`). Put a TLS terminator in front of it, or give n8n
   a certificate itself with `N8N_PROTOCOL=https`, `N8N_SSL_KEY=/path/key.pem` and
   `N8N_SSL_CERT=/path/cert.pem`. For a certificate n8n signed itself, set `pin_sha256` on
   the target to its fingerprint: the digits only, not the label. The command
   `openssl x509 -in cert.pem -noout -fingerprint -sha256` prints
   `SHA256 Fingerprint=AA:BB:...`; paste what follows the `=`, because the field refuses the
   label. If n8n is at a private address, also set `allow_internal: true` on the target.
2. **The Webhook node:** HTTP Method `POST`, a Path such as `certmate`, Respond
   *Immediately*, and publish the workflow. The target must call the **production** URL
   (`https://host:5678/webhook/certmate`), not the test one.
3. **What the node receives.** `$json.body` is the payload you wrote, so the example above
   gives `{{ $json.body.certificates.fullchain }}` and so on, as an ordinary multi-line
   PEM string. The headers are in `$json.headers`: `x-certmate-event`, `idempotency-key`
   (the same for a retry of one delivery, so a workflow can ignore a repeat) and
   `user-agent: CertMate-Deploy/1`. In the check, every certificate arrived identical to
   the file, the PKCS#8 key identical to `privkey.pem`, and the key in the traditional
   form (`RSA PRIVATE KEY` or `EC PRIVATE KEY`) was the key of the certificate, for an RSA
   and an EC certificate.

**n8n keeps what it receives.** With its default settings n8n stored every request body
in its own database, and in the check the private key could be read out of that
execution data. Treat n8n's database and its backups as holding the key, or leave the key
variables out of an n8n target and fetch the key some other way. Setting the workflow not
to save executions did **not** behave as expected in the same check (the executions stayed
in the `running` state with their data), so do not rely on that setting without looking at
what your own instance stores. This is the case the table above means by "a receiver that
keeps what it is sent".

---

## See also

- [`modules/core/deployer.py`](../modules/core/deployer.py) — implementation
- [`modules/core/deploy_targets.py`](../modules/core/deploy_targets.py) — typed deploy targets
- [`modules/web/settings_routes.py`](../modules/web/settings_routes.py) — `/api/deploy/*` endpoints
- [`templates/partials/settings_deploy.html`](../templates/partials/settings_deploy.html) — UI partial
- [`static/js/settings-deploy.js`](../static/js/settings-deploy.js) — Alpine component
