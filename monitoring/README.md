# CertMate monitoring

Ready-to-import Grafana dashboard, Prometheus alert rules, and a scrape config
for CertMate's Prometheus endpoint (`GET /metrics`).

## Files

| File | What it is |
| --- | --- |
| `grafana-dashboard.json` | Grafana dashboard (19 panels) — certificate health, issuance/renewal outcomes, ACME errors, DNS API calls, cache, uptime |
| `prometheus-alerts.yml` | Prometheus alerting rules — expiry, expired/failed states, ACME errors, rate limits, scrape-down |
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

The dashboard and alerts use only metrics CertMate emits today:

- **Inventory (gauges, refreshed every scrape):** `certmate_domains_total`,
  `certmate_certificates_total`, `certmate_certificates_by_status` (`valid`,
  `expiring_soon`, `expired`, `missing`, `renewal_failed`),
  `certmate_certificates_by_provider`, `certmate_certificate_expiry_days`
  (clamped at 0 — an expired cert reads 0), `certmate_dns_provider_accounts`,
  `certmate_application_uptime_seconds`, `certmate_cache_entries`,
  `certmate_version_info`.
- **Operations (counters/histograms, on real events):**
  `certmate_certificate_requests_total`, `certmate_certificate_renewals_total`,
  `certmate_certificate_creation_duration_seconds`,
  `certmate_certificate_renewal_duration_seconds`, `certmate_acme_errors_total`,
  `certmate_acme_rate_limit_hits_total`, `certmate_dns_provider_api_calls_total`,
  `certmate_cache_hits_total`, `certmate_cache_misses_total`.

Deliberately **not** used:

- `certmate_certificate_last_renewal_timestamp` /
  `certmate_certificate_next_renewal_timestamp` — currently derived from the
  renewal threshold rather than real renewal events, so they would mislead.
- `certmate_background_job_last_run_timestamp` /
  `certmate_background_job_duration_seconds` — reserved; not emitted yet (no
  caller records background-job runs). Don't build alerts on them until they are.
