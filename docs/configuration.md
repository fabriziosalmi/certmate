# Configuration

Every environment variable CertMate reads, its default, and what it changes. Everything else is a setting, changed in the web interface or through the [API](./api.md).

| Variable           | Required | Default        | Description                         |
| ------------------ | -------- | -------------- | ----------------------------------- |
| `API_BEARER_TOKEN`      |          | auto-generated | Bearer token for API authentication |
| `API_BEARER_TOKEN_FILE` |          | -              | Path to a file containing the API bearer token (takes precedence over `API_BEARER_TOKEN`) |
| `SECRET_KEY`            |          | auto-generated | Flask secret key for sessions       |
| `SECRET_KEY_FILE`       |          | -              | Path to a file containing the Flask secret key (takes precedence over `SECRET_KEY`). **If set and unreadable or empty, CertMate refuses to start** rather than inventing one: a secret that failed to mount is a configuration error, and a fresh key would sign out every user on every restart |
| `PORT`             |          | `8000`         | Server port (honoured by the container entrypoint) |
| `FLASK_ENV`        |          | `production`   | Flask environment. `production` refuses `--debug`  |
| `CERTMATE_LOG_FILE` |         | -              | Also write logs to this path. Off by default: the container logs to stdout, which is what `docker logs` and log shippers expect. Set it (e.g. `/app/logs/certmate.log`) to keep a file on the mounted volume — it is what the web UI's log stream reads |
| `CERTMATE_LOG_MAX_BYTES` |    | `10485760`     | Rotate the log file at this size (10 MB). File logging is always rotated — there is no way to configure an unbounded one |
| `CERTMATE_LOG_BACKUP_COUNT` | | `5`            | How many rotated files to keep (~60 MB ceiling with the default size) |
| `CERTMATE_AUDIT_LOG_MAX_BYTES` | | `10485760`  | Rotate the human-readable audit log (`logs/audit/certificate_audit.log`) at this size. `0` disables rotation. Does **not** apply to the tamper-evident hash chain in `data/audit/`, which is never rotated |
| `CERTMATE_AUDIT_LOG_BACKUP_COUNT` | | `5`       | How many rotated audit logs to keep. Note the Activity page tails only the active file, so it shows fewer entries immediately after a roll |
| `CERTMATE_LOG_LEVEL` |        | `INFO`         | DEBUG / INFO / WARNING / ERROR |
| `CERTMATE_LOG_JSON` |         | `true`         | JSON log lines (set `false` for human-readable) |

## Deployment and networking

| Variable           | Required | Default        | Description                         |
| ------------------ | -------- | -------------- | ----------------------------------- |
| `BEHIND_PROXY`     |          | `false`        | Trust `X-Forwarded-*` from one reverse proxy hop (`ProxyFix`). Set it only when a proxy actually sits in front: with it on and no proxy, a client can forge its own address, which is what the login rate limit is keyed on |
| `PREFERRED_URL_SCHEME` |      | -              | Set to `https` when TLS terminates in front of CertMate. It marks the session cookie `Secure`, so the browser stops sending it over plain HTTP |
| `CORS_ORIGINS`     |          | -              | Comma-separated origins allowed to call the API from a browser. Empty means the built-in default; this is not a way to open the API to everyone |
| `ACME_CHALLENGES_DIR` |       | `<cwd>/data/acme-challenges` | Where http-01 tokens are written and served from. Override it when the webroot is somewhere else; the hook, the pre-creation and the route all read this one value |
| `LETSENCRYPT_EMAIL` |         | -              | ACME account email. **Takes precedence over the value saved in the UI**, so an instance that keeps changing its email back is usually this |
| `CLOUDFLARE_TOKEN` |          | -              | Seeds the default Cloudflare DNS account on first start, so a container can be brought up already able to issue. Once settings.json exists the stored value is what is used |

## Security behaviour

| Variable           | Required | Default        | Description                         |
| ------------------ | -------- | -------------- | ----------------------------------- |
| `CERTMATE_ENABLE_HSTS` |      | `false`        | Send `Strict-Transport-Security`, and mark the session cookie `Secure`. Only set it when TLS really terminates in front — an HSTS header on a plain-HTTP instance locks browsers out of it |
| `SESSION_TIMEOUT_HOURS` |     | `8`            | How long a login session stays valid. The server record and the browser cookie both use this value, so they cannot drift apart |
| `CERTMATE_ALLOW_INTERNAL_WEBHOOKS` | | `false` | Allow notification webhooks to private, loopback and link-local addresses. Off by default because a webhook URL is operator-supplied and an SSRF into the host network is the obvious abuse |
| `CERTMATE_PROBE_ALLOW_PRIVATE` | |  `false`      | Same relaxation for the certificate probe behind `POST /api/probe` (discovery sweeps ignore it and use `monitored_endpoints.allow_private` from settings): allow it to connect to private addresses. Needed to probe a service on the same host, and it removes an SSRF guard |
| `CERTMATE_AUDIT_CHAIN` |      | `1`            | Set `0` to stop writing the tamper-evident audit hash chain. A kill switch, not a tuning knob: with it off, `/api/audit/verify` can no longer prove the log was not edited |
| `AUDIT_SIGNING_KEY_FILE` |    | -              | Path to an Ed25519 private key that signs audit checkpoints, so the key can live off this box. If set and unreadable, signing is DISABLED rather than a new key generated — a fresh key would fork the instance's identity and make earlier signatures unverifiable |
| `CERTMATE_ALLOW_SCHEMA_DOWNGRADE` | | `0`       | Set `1` to let this build read and overwrite a `settings.json` or `metadata.json` written by a NEWER version. It will drop fields it does not understand — that is the whole reason it refuses by default |

## Client certificates

The private CA that signs client certificates is created once, on the first
start. These name it before that happens, so a new instance does not have to
boot as `CertMate CA` and then be reset. A variable left unset — or empty, which
is how the compose files pass one you did not set — keeps the default for its
field. `client_ca_subject` in settings, when present, takes precedence. Like
that setting, they are read **only when the CA is created**: changing them
later does not replace an existing CA, so every client certificate it signed
keeps verifying. To apply them to an instance that already has a CA, restart
with the new values and send `POST /api/client-certs/ca/reset` without a
`subject` ([docs/api.md](./api.md#rebuild-the-client-certificate-authority)).

| Variable                                 | Required | Default                 | Description |
| ---------------------------------------- | -------- | ----------------------- | ----------- |
| `CERTMATE_CLIENT_CA_COUNTRY`             |          | `CH`                    | Country (`C`) of the client CA. A two-letter ISO 3166-1 code; anything else stops the start before a key is written |
| `CERTMATE_CLIENT_CA_STATE`               |          | `Switzerland`           | State or province (`ST`) of the client CA |
| `CERTMATE_CLIENT_CA_ORGANIZATION`        |          | `CertMate`              | Organisation (`O`) of the client CA |
| `CERTMATE_CLIENT_CA_ORGANIZATIONAL_UNIT` |          | `Certificate Authority` | Organisational unit (`OU`) of the client CA |
| `CERTMATE_CLIENT_CA_COMMON_NAME`         |          | `CertMate CA`           | Common name (`CN`) of the client CA: the issuer name every client certificate shows |
| `CERTMATE_CLIENT_CERT_DEFAULT_COUNTRY`   |          | `CH`                    | Country of a client certificate issued without one: a create request that leaves it out, every CSV batch row, and every renewal. A value in the request wins. Not a two-letter code: the instance refuses to start, naming the variable |
| `CERTMATE_CLIENT_CERT_DEFAULT_STATE`     |          | `Switzerland`           | State or province of a client certificate issued without one, in the same cases |

## Timing and diagnostics

| Variable           | Required | Default        | Description                         |
| ------------------ | -------- | -------------- | ----------------------------------- |
| `CERTMATE_DOMAIN_LOCK_TIMEOUT` | | `5`         | Seconds to wait for a domain's lock before answering 409 "operation in progress". Clamped to 0-60 |
| `CERTMATE_CERT_INFO_CACHE_TTL` | | `60`        | Seconds a parsed certificate's details stay cached. `0` re-reads from disk on every request. Clamped to 0-3600 |
| `CERTMATE_ISSUANCE_WORKERS` | | `2`            | Threads serving asynchronous issuance jobs. Clamped to 1-16; each one can be running a certbot subprocess |
| `CERTMATE_CERT_DIR` |    | `<install>/certificates` | Where issued certificates live. Absolute, or relative to the working directory. The local storage backend follows it too, unless `certificate_storage.cert_dir` names a directory of its own |
| `CERTMATE_DATA_DIR` |    | `<install>/data`         | Settings, the certificate inventory and the audit chain |
| `CERTMATE_BACKUP_DIR` |  | `<install>/backups`      | Where backups are written and restored from |
| `CERTMATE_LOGS_DIR` |    | `<install>/logs`         | Application and audit logs |
| `CERTMATE_ISSUANCE_QUEUE_LIMIT` | | `20`        | How much unfinished issuance may exist at once, counting queued and running jobs. Clamped to 1-500. Beyond it the async endpoints answer `429 ISSUANCE_QUEUE_FULL` instead of accepting work that will not be reached for hours |
| `CERTMATE_ISSUANCE_JOB_HISTORY` | | `200`      | How many finished issuance jobs stay queryable via `/api/certificates/jobs`. Clamped to 20-2000 |
| `CERTMATE_EVENT_WORKERS` |    | `4`            | Threads dispatching event listeners (deploy hooks, cache invalidation). Clamped to 1-32. Nothing is dropped when they are busy; the backlog is logged instead |
| `CERTMATE_EVENT_MAX_STREAMS` |    | `4`            | Live `/api/web/events/stream` connections held at once. Each one occupies a gunicorn thread and the image runs `--workers 1 --threads 8`, so this leaves half the pool for ordinary requests. Past it the route answers `503` with `Retry-After`. Clamped to 1-64 |
| `CERTMATE_EVENT_STREAM_SECONDS` |    | `900`          | How long one event stream is held before it is closed and the browser reconnects. `EventSource` reconnects on its own, so this is invisible — it bounds what a forgotten tab can hold. Clamped to 30-86400 |
| `CERTMATE_EVENT_DRAIN_SECONDS` |    | `5`            | How long a shutdown waits for queued event dispatches to start before giving up on them. Clamped to 0-60. Whatever is left is logged with its event and domain, so a deploy hook that never ran after a renewal is named rather than lost |
| `CERTMATE_CERTBOT_PROBE_TTL` |    | `300`          | Seconds before the certbot readiness answer is re-checked. Clamped to 30-3600. The probe used to run once per process, so a transient failure at boot made the instance permanently unready and a certbot that broke later never turned `/health/ready` red |
| `CERTMATE_PROBE_TIMEOUT_SECONDS` | | `5`       | Connection timeout of the certificate probe used by discovery sweeps and `POST /api/probe`. Clamped to 1-30. The deployment check has its own, `CERTMATE_TLS_PROBE_TIMEOUT_SECONDS` |
| `CERTMATE_LAST_USED_PERSIST_SECONDS` | | `60`  | How often a session's "last used" timestamp is written to disk. `0` writes on every request, which is the original behaviour and one write per request |
| `CERTMATE_SLOW_REQUEST_LOGGING` | | `true`       | Log a warning, with the thread's stack, for requests that outlive the threshold below. The stack is what makes a hung request diagnosable after the fact |
| `CERTMATE_SLOW_REQUEST_THRESHOLD_SECONDS` | | `30` | How long a request must run before it is reported |
| `CERTMATE_SLOW_REQUEST_SCAN_SECONDS` | | `10`  | How often the watchdog looks for requests that are still running |
| `CERTMATE_SLOW_REQUEST_REPEAT_SECONDS` | | threshold | How often a still-running request is reported again |

> **Bind address is not an environment variable.** The container always binds
> `0.0.0.0` inside its own network namespace; to expose it only on loopback,
> publish it that way — `-p 127.0.0.1:8000:8000`. Running `app.py` directly
> (development only) takes `--host` / `--port` / `--debug` as CLI flags.
> `HOST` and `FLASK_DEBUG` are read by nothing, and setting them has never
> had any effect (#429).
