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

### What is recorded, and the one thing that is not

Everything the dashboard and the alerts use is recorded at runtime. That was
not always true — this section used to list eight metrics that were defined and
never incremented, which is worse than a missing metric: a panel built on one
shows a flat line, and an alert on one never fires, so both read as "nothing is
going wrong".

Recorded on the operations side:

- `certmate_certificate_renewals_total` and
  `certmate_certificate_renewal_duration_seconds` — by the renewal sweep, on
  both the success and the failure path.
- `certmate_certificate_requests_total` and
  `certmate_certificate_creation_duration_seconds` — by the issuance path,
  on success, on failure and on the certbot timeout.
- `certmate_acme_errors_total` — on any failed issuance or renewal, labelled
  with the exception type.
- `certmate_acme_rate_limit_hits_total` — when the CA's refusal is a rate
  limit rather than a fault, which is a different thing to do about it.
- `certmate_cache_hits_total` / `_misses_total` — at the deployment-status
  cache lookup itself.
- `certmate_background_job_last_run_timestamp` / `_duration_seconds` — by the
  background-job wrapper, on both paths, which is what makes "the sweep has
  not run in N days" a writable alert.
- `certmate_renewal_sweep_*` — duration, certificates examined, completion
  time, and whether the last sweep finished.
- `certmate_certificate_last_renewal_timestamp` / `_next_renewal_timestamp` —
  from the real event in the certificate's metadata, not derived from the
  expiry date.

`certmate_certificates_by_status` had a fifth label, `renewal_failed`, which
nothing ever assigned: every scrape exported it as 0. It has been removed
rather than populated, because it is not a state a certificate is *in* — one
whose renewal failed is still `valid`, `expiring_soon` or `expired`. The
failure is an event, and it is counted as one by
`certmate_certificate_renewals_total{status="failure"}`, which the renewal
sweep increments and which the `CertMateRenewalsFailing` rule alerts on. A
constant zero is worse than an absent series: an alert written against it can
never fire, and reads as "no failures ever".

There is no `certmate_dns_provider_api_calls_total`. It was defined and never
recorded, and it cannot be recorded from where those calls happen: certbot
talks to the DNS provider in its own subprocess, and CertMate's own DNS-alias
hook is a separate short-lived process whose counters die with it. It was
removed rather than left exported.
