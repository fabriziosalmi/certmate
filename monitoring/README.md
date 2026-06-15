# CertMate monitoring

Ready-to-import Grafana dashboard, Prometheus alert rules, and a scrape config
for CertMate's Prometheus endpoint (`GET /metrics`).

## Files

| File | What it is |
| --- | --- |
| `grafana-dashboard.json` | Grafana dashboard (11 panels) — certificate inventory, days-until-expiry, status & provider breakdowns, cache, uptime, version |
| `prometheus-alerts.yml` | Prometheus alerting rules (4) — expiring soon/critical, expired, scrape-down |
| `prometheus-scrape.example.yml` | Example authenticated scrape job |

## Scrape setup

`/metrics` requires the **admin** role. Create a dedicated admin-scoped API
token (Settings > API Keys) and present it as a Bearer credential — see
`prometheus-scrape.example.yml`. Then load the alert rules:

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/certmate-alerts.yml
```

## Import the dashboard

Grafana > Dashboards > New > Import > Upload `grafana-dashboard.json`, then pick
your Prometheus datasource when prompted. The dashboard is keyed by uid
`certmate-overview` and tagged `certmate`.

## Metric coverage

The dashboard and alerts use **only metrics the `/metrics` endpoint actually
populates** — the certificate inventory gauges, refreshed on every scrape:
`certmate_domains_total`, `certmate_certificates_total`,
`certmate_certificates_by_status` (`valid`, `expiring_soon`, `expired`,
`missing`), `certmate_certificates_by_provider`,
`certmate_certificate_expiry_days` (clamped at 0 — an expired cert reads 0),
`certmate_dns_provider_accounts`, `certmate_application_uptime_seconds`,
`certmate_cache_entries`, `certmate_version_info`.

> Populating these requires the `/metrics` route to pass a collection context
> (settings, cert dir, cache). That wiring ships alongside this bundle; without
> it the endpoint emits only `application_uptime`.

### Not yet included (needs instrumentation)

These metrics are **defined but never recorded at runtime**, so any panel or
alert on them would read "No data" / never fire. They are deliberately left
out until the code is instrumented, at which point the operations row and the
renewal/ACME alerts can be added back:

- Operations counters/histograms — `certmate_certificate_requests_total`,
  `certmate_certificate_renewals_total`, the `*_duration_seconds` histograms,
  `certmate_acme_errors_total`, `certmate_acme_rate_limit_hits_total`,
  `certmate_dns_provider_api_calls_total`, `certmate_cache_hits_total` /
  `_misses_total`: no `record_*` caller exists yet.
- `certmate_certificates_by_status{status="renewal_failed"}`: the status is
  never assigned, so it is constant 0.
- `certmate_certificate_last_renewal_timestamp` /
  `_next_renewal_timestamp`: derived from the renewal threshold, not real
  events — would mislead.
- `certmate_background_job_last_run_timestamp` / `_duration_seconds`:
  reserved; no caller records background-job runs.
