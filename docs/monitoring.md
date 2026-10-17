# Monitoring

How to tell that CertMate is up and still renewing, how to scrape its metrics,
where its logs go, and how it tells you when something needs attention.

## Health endpoints

Three endpoints answer without a credential, so a load balancer or an
orchestrator can poll them:

| Endpoint | Status code | What it checks | Use it for |
| --- | --- | --- | --- |
| `GET /health` | always `200` while the web server answers | the scheduler, certbot, the certificate directory, free disk space (`low` under 100 MB) | liveness: `status` is `healthy` or `degraded` |
| `GET /health/ready` | `200`, or `503` when the scheduler is not running or certbot cannot run | whether automatic renewals can happen | readiness probes and deploy gates |
| `GET /api/health` | `200` when healthy or degraded, `500` when unhealthy | settings, the scheduler, the storage backend | see the [API reference](./api.md#health-check) |

```bash
# Succeeds whenever the server answers; read "status" to see a degraded instance
curl -fsS http://localhost:8000/health

# Fails (503) when nothing would renew: the scheduler or certbot is down
curl -fsS http://localhost:8000/health/ready
```

`/health` stays `200` on purpose, so a load balancer keeps routing to an
instance that still serves the UI and the API. That is also why it cannot
tell you that renewals have stopped: `/health/ready` is the one that turns
red when they have.

The Docker image's `HEALTHCHECK` and the stock `docker-compose.yml` poll
`/health`.

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
