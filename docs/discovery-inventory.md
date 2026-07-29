# Certificate Discovery & Inventory

CertMate historically only knew about the certificates it **issued**. The
discovery & inventory feature lets it also record certificates it merely
**observes** — served on a host, or logged in Certificate Transparency — so you
get one place that answers "what certificates exist across my estate, who issued
them, when do they expire, and which cryptography do they use?"

This guide covers:

1. [How it fits together](#how-it-fits-together)
2. [The deep TLS probe](#the-deep-tls-probe)
3. [The inventory model](#the-inventory-model)
4. [Endpoint discovery](#endpoint-discovery)
5. [CT-log monitoring (crt.sh)](#ct-log-monitoring)
6. [The Inventory dashboard](#the-inventory-dashboard)
7. [Adopting a discovered certificate](#adopting-a-discovered-certificate)
8. [Cryptographic readiness report](#cryptographic-readiness-report)
9. [API reference](#api-reference)
10. [Security model](#security-model)

Everything here is **opt-in**: an upgrade never starts probing external hosts or
polling CT logs until you enable it.

---

## How it fits together

```
                       ┌──────────────────────────────┐
  scheduled sweep ───▶ │  deep TLS probe (host:port)  │──┐
  (04:00 daily)        └──────────────────────────────┘  │
                       ┌──────────────────────────────┐  ├─▶  inventory
  CT-log poll ───────▶ │  crt.sh monitor (per domain) │──┤    (SQLite, keyed by
  (05:00 daily)        └──────────────────────────────┘  │     SHA-256 fingerprint)
                       ┌──────────────────────────────┐  │
  certificates you ──▶ │  issued by CertMate          │──┘
  issue                └──────────────────────────────┘
                                     │
                       Inventory dashboard · Adopt · Crypto readiness report
```

Each certificate is stored **once**, keyed by its SHA-256 fingerprint. One
certificate served on many hosts is a single record with many endpoints.

---

## The deep TLS probe

The probe connects to a `host:port`, reads the served certificate, and returns
full structured metadata:

- Subject CN + complete **SAN** list
- **Serial** (decimal + hex) and **SHA-256 fingerprint** (stable identity)
- `notBefore` / `notAfter` and days-until-expiry
- Full **issuer DN**
- **Public-key** algorithm + size/curve (RSA / ECDSA / Ed25519 / Ed448 / DSA)
- **Signature** algorithm
- The served chain where the peer sends one

It intentionally does **not** validate PKI trust, so it still fully describes an
expired, self-signed, or hostname-mismatched certificate — a `validation` block
reports those conditions instead of a bare error. IPv6 and any port are
supported. See also the reachability probe in [Probes](./probes.en.md).

---

## The inventory model

A record carries:

| Field | Notes |
|---|---|
| `fingerprint` | SHA-256, the primary key |
| `subject_cn`, `subject`, `issuer_cn`, `issuer` | identity |
| `serial`, `not_before`, `not_after` | validity |
| `key` | `{type, size, curve}` |
| `signature_algorithm` | |
| `san_dns` | DNS SANs |
| `source` | `issued` \| `probed` \| `ct-log` \| `imported` |
| `managed` | whether CertMate manages it, with `managed_domain` linking it |
| `first_seen` / `last_seen` | |
| `endpoints[]` | every `host:port` it was observed at, each with its own first/last-seen |

Records are created and updated **idempotently** by fingerprint: re-observing a
certificate only refreshes `last_seen` and merges the endpoint; the cryptographic
metadata is immutable (the fingerprint *is* its hash). `source` is preserved from
first discovery; `managed` is sticky-true.

Storage is a single SQLite database at `<data_dir>/inventory/inventory.db`. It is
included in the [unified backup](./guide.md) alongside the PKI and audit chain,
so a restore never silently loses discovered-cert history.

---

## Endpoint discovery

Configure a list of endpoints to probe on a schedule. The sweep runs daily at
04:00 and upserts each reachable certificate into the inventory. Managed domains
CertMate already issues for are probed too (by default), so you can compare
"what we issued" against "what is actually being served" — catching, for example,
a renewed certificate that was never deployed.

```jsonc
{
  "monitored_endpoints": {
    "enabled": true,
    "endpoints": ["example.com", "api.example.com:8443", "[2001:db8::1]:443"],
    "include_managed": true,     // also probe the hosts of managed domains
    "allow_private": false       // refuse private/loopback targets (SSRF guard)
  }
}
```

Endpoint specs accept `host`, `host:port` (default 443), a bare IPv6 literal, or
a bracketed `[v6]:port`. The sweep is **failure-isolated**: a bad spec, an
unreachable host, or an inventory error is recorded as a per-endpoint status and
never aborts the run or blocks certificate operations.

Trigger a sweep immediately from the dashboard ("Scan now") or
`POST /api/inventory/scan`.

---

## CT-log monitoring

Endpoint probing only finds certificates on hosts you already know about.
**Certificate Transparency** makes shadow / forgotten issuance visible: CertMate
polls [crt.sh](https://crt.sh) for your domains (daily at 05:00) and adds
newly-seen certificates with `source=ct-log`, flagged unmanaged — a certificate
in CT that CertMate doesn't manage is exactly the shadow-issuance signal to
investigate.

```jsonc
{
  "ct_monitoring": {
    "enabled": true,
    "domains": ["example.com", "example.org"],
    "include_managed": true,
    "only_valid": true,          // ignore already-expired CT entries
    "max_new_per_run": 100,      // cap new ingestions per run (truncation is logged)
    "min_request_interval": 2.0  // seconds between crt.sh requests
  }
}
```

crt.sh's JSON gives an issuer + serial but not the SHA-256 fingerprint. To avoid
fetching every historical certificate, the poll deduplicates by **serial**
against the inventory first and only downloads the DER (to compute the true
fingerprint) for certificates it has never seen — so known certs cost no extra
requests. Polling is rate-limited and failure-isolated per domain and per entry.

---

## The Inventory dashboard

`/inventory` shows every issued and discovered certificate in two groups —
**Issued by CertMate** and **Discovered / unmanaged** — with columns for
subject/SAN, issuer, expiry (days remaining + status colour), key
algorithm/size, source, and endpoints. Filter by group, source, expiry, or free
text. Summary cards give an **expiry forecast** (expired / within 7 / 30 / 90
days) across *everything*, not just issued certs.

Admins get an inline configuration panel for the monitored endpoints and CT-log
domains, plus **Scan now**.

---

## Adopting a discovered certificate

When the inventory shows a discovered, unmanaged certificate whose domain
CertMate can validate (DNS credentials present + an ACME account email set), an
**Adopt** action pre-fills the create form from the *observed* certificate
(domain, SANs, key type) so you confirm rather than retype, issues it, and
brings it under CertMate's normal renewal schedule.

If the domain can't be validated, the action explains why (missing DNS
credentials or email) instead of offering a dead end.

---

## Cryptographic readiness report

`/inventory/crypto-report` enumerates every managed and discovered certificate by
public-key algorithm/size and signature algorithm, and classifies each as
**weak** / **acceptable** / **modern**, flagging everything classically
quantum-vulnerable. It maps legacy assets against published deprecation guidance
(informational) — the prerequisite for crypto-agility planning and, in the EU, a
crypto-inventory obligation. See also [Compliance](./compliance.md).

The classification table is **data-driven** so new algorithms (e.g. ML-DSA,
composite/hybrid) can be added without code changes. This is framed strictly as
**inventory / readiness** — it does not change certificate issuance and says
nothing about issuing post-quantum certificates.

Export as **JSON** or **CSV** (`?format=csv`), or open the print-friendly report
and "Print / Save as PDF".

---

## API reference

All endpoints require at least a `viewer` credential; writes require `admin`
(config/scan) or `operator` (adopt). Scoped API keys only see records whose
subject/SAN falls within their `allowed_domains`.

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/inventory` | viewer | List records + expiry summary (`?managed=`, `?source=`) |
| GET | `/api/inventory/config` | viewer | Discovery + CT-log configuration |
| POST | `/api/inventory/config` | admin | Update discovery / CT-log config |
| POST | `/api/inventory/scan` | admin | Run a discovery sweep + CT poll now |
| GET | `/api/inventory/crypto-report` | viewer | Readiness report (`?format=csv`) |
| GET | `/api/inventory/<fingerprint>/adopt` | viewer | Adoption plan (feasibility + pre-fill) |
| POST | `/api/inventory/<fingerprint>/adopt` | operator | Adopt & manage the certificate |

---

## Security model

- **Opt-in.** `monitored_endpoints` and `ct_monitoring` both default to
  `enabled: false`. Nothing probes or polls until you turn it on.
- **SSRF guard.** The probe resolves a target first and refuses private,
  loopback, link-local, reserved, multicast, CGNAT (`100.64.0.0/10`) and any
  other non-globally-routable address — including IPv4-mapped IPv6 — unless
  `allow_private` is set. The validated IP is pinned for the connection with SNI
  set to the hostname, so a DNS rebind between the check and the handshake cannot
  redirect the probe to an internal host.
- **Domain scope.** A scoped API key only sees inventory records within its
  `allowed_domains`, the same boundary the certificate API enforces.
- **CSV safety.** Certificate fields come from untrusted (probed / CT-logged)
  certificates; CSV export neutralises spreadsheet formula-injection leads.
- **Failure isolation.** Every sweep/poll is failure-isolated per item, so
  discovery can never stall or abort a certificate operation.
