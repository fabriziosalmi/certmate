# Monitoring

How to tell that CertMate is up and still renewing, how to scrape its metrics,
where its logs go, and how it tells you when something needs attention.

## Health endpoints

Three endpoints answer without a credential, so a load balancer or an
orchestrator can poll them:

| Endpoint | Status code | What it checks | Use it for |
| --- | --- | --- | --- |
| `GET /health` | `200` while requests still finish, `503` when they have stopped (see below) | the scheduler, certbot, the certificate directory, free disk space (`low` under 100 MB), whether requests still finish | liveness: `status` is `healthy`, `degraded` or `unhealthy` |
| `GET /health/ready` | `200`, or `503` when the scheduler is not running or certbot cannot run | whether automatic renewals can happen | readiness probes and deploy gates |
| `GET /api/health` | `200` when healthy or degraded, `500` when unhealthy | settings, the scheduler, the storage backend | see the [API reference](./api.md#health-check) |

```bash
# Succeeds whenever the server answers; read "status" to see a degraded instance
curl -fsS http://localhost:8000/health

# Fails (503) when nothing would renew: the scheduler or certbot is down
curl -fsS http://localhost:8000/health/ready
```

`/health` stays `200` for a degraded instance on purpose, so a load balancer
keeps routing to an instance that still serves the UI and the API. That is
also why it cannot tell you that renewals have stopped: `/health/ready` is the
one that turns red when they have.

### The health port

CertMate serves the web UI and the API on a fixed number of threads
(`GUNICORN_THREADS`, 8 in the image). When slow requests hold all of them,
`/health` on the request port waits like any other request. Measured with
2,000 certificates: 8 overlapping listings held the 8 threads for 45 seconds,
and `/health` timed out, so a healthcheck with a 10-second timeout counted
failures while every check was fine.

So the same report is also served on `HEALTH_PORT`, by a server on a thread of
its own that no request can take:

```bash
curl -fsS http://localhost:8001/health
```

The image sets `HEALTH_PORT=8001`, and its `HEALTHCHECK`, both compose files
and the Helm chart's liveness and readiness probes ask that port. The port
serves `GET /health` and nothing else. It is not published by the compose
files: the checks run inside the container. Without `HEALTH_PORT` (a
bare-metal install, unless you set it) no second port is opened, and
`/health` on the request port works as before.

A health check that always answers would hide a server whose threads are
stuck for good, and nothing would restart it. So the report also says whether
requests still finish:

| Field | Meaning |
| --- | --- |
| `checks.requests` | `progressing`, or `stalled` when every request thread has been busy and none has finished for `CERTMATE_HEALTH_STALL_SECONDS` |
| `checks.requests_in_flight` | requests being served right now, streams included |

`stalled` makes `status` `unhealthy` and the answer `503`, on both ports, so
`curl -f` and the probes fail and the supervisor restarts the container. A
request that finishes, or a thread that comes free, ends the stall.

| Variable | Default | Effect |
| --- | --- | --- |
| `HEALTH_PORT` | `8001` in the image, unset elsewhere | the port of the health server; unset opens no port |
| `HEALTH_HOST` | `0.0.0.0` | the address it listens on |
| `GUNICORN_THREADS` | `8` | the request threads, read by gunicorn and by the stall check |
| `CERTMATE_HEALTH_STALL_SECONDS` | a minute past `GUNICORN_TIMEOUT` (`360` in the image) | how long every thread may be busy with nothing finishing. Not less than `GUNICORN_TIMEOUT`: a request may run that long by design, as issuance waits for DNS-01 propagation, and a restart would throw its work away |

The open event and log streams hold a thread each for as long as a browser tab
keeps them, and count as busy: with 8 tabs open on 8 threads, nothing else
can be served, and the check says so.

## Prometheus metrics

`GET /metrics` serves the metrics in the Prometheus text format. It needs the
viewer role: create a viewer-scoped API key (Settings > API Keys) and present it
as a Bearer token. A scraper reads, so it does not need admin.

The [`monitoring/`](../monitoring/) folder ships what is needed to use them:

- `prometheus-scrape.example.yml`: an authenticated scrape job;
- `prometheus-alerts.yml`: 8 alert rules (certificates expiring soon,
  expiring critically or expired, CertMate down, renewals failing, issuance
  failing, ACME rate-limited, ACME errors);
- `grafana-dashboard.json`: a Grafana dashboard with 11 panels.

Setup and import steps are in [monitoring/README.md](../monitoring/README.md).

The metrics are declared in
[`modules/core/metrics.py`](../modules/core/metrics.py). The ones most worth an
alert of your own:

| Metric | Labels | What it says |
| --- | --- | --- |
| `certmate_certificate_expiry_days` | `domain`, `dns_provider` | days until each certificate expires |
| `certmate_renewal_sweep_completed_timestamp_seconds` | | when the last renewal sweep finished |
| `certmate_renewal_sweep_unfinished` | | certificates the last sweep did not get to |
| `certmate_acme_errors_total` | | errors returned by the ACME CA |

```promql
# Certificates that expire within 14 days
certmate_certificate_expiry_days < 14
```

An API key restricted with `allowed_domains` sees only the series for its own
domains and none of the totals; the dashboard and the alert rules above need a
key with no restriction.

## Logs

CertMate logs to stdout, one JSON object per line. Any Docker logging driver or
log shipper collects it as it is; there is nothing CertMate-specific to
configure.

| Variable | Default | Effect |
| --- | --- | --- |
| `CERTMATE_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |
| `CERTMATE_LOG_JSON` | `true` | `false` for human-readable lines |
| `CERTMATE_LOG_FILE` | not set | also write a rotated file at this path; the web UI's log stream reads it |

Rotation of that file is set by `CERTMATE_LOG_MAX_BYTES` and
`CERTMATE_LOG_BACKUP_COUNT`; see [Configuration](./configuration.md). Secrets are
redacted before a line
is written. To follow an issuance live from a terminal, see the
[log stream endpoint](./api.md#log-stream-admin-debugging).

## Notifications

Settings > Notifications configures the channels CertMate uses to tell you
that something happened:

- **Email (SMTP)**
- **Slack** (incoming webhook)
- **Discord** (webhook)
- **Google Chat** (webhook)
- **Telegram** (bot token and chat ID)
- **ntfy**: push to an [ntfy](https://ntfy.sh) topic, self-hostable, with an
  optional access token and a priority per message
- **Gotify**: push to a self-hosted [Gotify](https://gotify.net) server
  (server URL and app token)
- **Generic webhooks**: `POST`, `PUT` or `PATCH`, HMAC-SHA256 signatures,
  bearer, basic or header authentication, and a JSON payload template; see
  [webhooks.md](./webhooks.md)

Each channel can be tested from the same page.

> **Microsoft Teams:** no dedicated adapter is needed. Use a Teams channel's
> built-in email address (channel > ... > Get email address) as a recipient on
> the Email (SMTP) channel, and Teams posts the message into the channel.

### Events

A channel can be limited to some events. Six can be filtered:
`certificate_created`, `certificate_renewed`, `certificate_deployed`,
`certificate_expiring`, `certificate_revoked` and `domain_expiring`.

Three are always delivered, whatever the filter says, because they report a
failure nobody should be able to silence by accident:

- `certificate_failed`: an issuance or a renewal did not happen;
- `deploy_hook_failed`: a deploy hook failed, once per target;
- `certificate_deploy_incomplete`: a renewed certificate was obtained, but the
  systems that serve it may still present the previous one.

### Weekly digest

A summary of certificate status and upcoming renewals, sent by email through
the SMTP channel on Sundays at 00:00 server time. It is on whenever
notifications and the SMTP channel are enabled; the Weekly Digest toggle in
Settings > Notifications turns it off, and its **Send now** button sends one
immediately.
