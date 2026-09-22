# Certificate Discovery & Inventory

CertMate historically only knew about the certificates it **issued**. The
discovery & inventory feature lets it also record certificates it merely
**observes** — served on a host, or logged in Certificate Transparency — so you
get one place that answers "what certificates exist across my estate, who issued
them, when do they expire, and which cryptography do they use?"

This guide covers:

1. [How it fits together](#how-it-fits-together)
2. [The deep TLS probe](#the-deep-tls-probe)
   - [Revocation](#revocation)
3. [The inventory model](#the-inventory-model)
4. [Endpoint discovery](#endpoint-discovery)
5. [CT-log monitoring (crt.sh)](#ct-log-monitoring)
6. [The Inventory dashboard](#the-inventory-dashboard)
7. [Adopting a discovered certificate](#adopting-a-discovered-certificate)
8. [Cryptographic readiness report](#cryptographic-readiness-report)
9. [Domain registration expiry](#domain-registration-expiry)
10. [API reference](#api-reference)
11. [Security model](#security-model)

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

### Revocation

A certificate can be revoked by its issuer long before it expires, and a
revoked certificate still being served looks healthy on every other axis. When
a discovery sweep runs with `check_revocation` (the default), the probe also
asks the issuer:

1. **OCSP** first, at the responder named in the certificate's AIA extension.
2. **The CRL** when there is no responder, when it does not answer, or when it
   says it does not know the certificate. Let's Encrypt turned OCSP off in 2025,
   so for its certificates the CRL is the only source.

The issuer certificate comes from the served chain when the Python runtime can
hand it over (the one in the image cannot, so in practice this is the next
route) and otherwise from the certificate's AIA `caIssuers` URL. It must have
actually signed the certificate either way.

An answer counts only if it is **verified**. An OCSP response has to be signed
by the issuer, or by a responder the issuer signed that carries the OCSP-signing
extended key usage, and it has to be current. A CRL has to be issued and signed
by the issuer and not be past its `nextUpdate`. Anything short of that is
reported as `unavailable` with the reason, never as `good`:

| `revocation.status` | Meaning |
|---|---|
| `good` | a verified OCSP or CRL answer says it is not revoked |
| `revoked` | a verified answer says it is; `revoked_at` and `reason` carry what the issuer published |
| `unknown` | the OCSP responder does not know the certificate and no CRL settled it |
| `unavailable` | no verified answer could be obtained; `error` says why |
| `not_applicable` | self-signed, so there is no issuer to revoke it |
| *(null)* | never checked: revocation checking is off, or the certificate has not been swept since |

`revoked` is final. A later sweep in which the responder is down, or even one
that gets a different answer, does not overwrite it, because a CA cannot
un-revoke a certificate.

The requests go to the OCSP and CRL URLs written in the certificate, which for a
discovered certificate means URLs chosen by whoever issued it. They pass through
the same SSRF guard as the probe, only plain `http` is fetched (the payloads are
signed, so TLS would add nothing), redirects are not followed, and responses are
size-capped. The issuer certificate and each CRL are cached for the sweep, so
a hundred hosts behind one CA cost one CRL download.

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
| `revocation` | the last verified revocation answer: `{status, method, reason, revoked_at, error, checked_at}`, or `null` if never checked (see [Revocation](#revocation)); since API contract **2.4** |

Records are created and updated **idempotently** by fingerprint: re-observing a
certificate only refreshes `last_seen` and merges the endpoint; the cryptographic
metadata is immutable (the fingerprint *is* its hash). `source` is preserved from
first discovery; `managed` is sticky-true. The revocation answer is the one
mutable part, updated on every checked sweep, except that `revoked` is final.

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
    "allow_private": false,      // refuse private/loopback targets (SSRF guard)
    "check_revocation": true     // ask OCSP, then the CRL (see Revocation)
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
days) across *everything*, not just issued certs, plus a count of certificates
a verified answer says are **revoked**. Each row shows its revocation answer
under the expiry badge; a certificate that could not be checked says so in grey
and gives the reason on hover, rather than looking fine.

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

## Domain registration expiry

A certificate that renews on time is worth nothing on a domain whose
registration lapsed: the name stops resolving, and every certificate under it
goes with it. The inventory therefore also tracks when each **domain** expires.

It follows every *registrable* domain CertMate knows about, each asked once
however many hosts sit under it: `www.shop.example.co.uk` and `api.example.co.uk`
are both `example.co.uk`. The set is:

- every managed domain and its SANs;
- what discovery found (probed endpoints, CT-log entries), unless
  `include_inventory` is off;
- any `extra_domains` you list.

Names are reduced with the Public Suffix List bundled in `tldextract`, read
offline. Where the answer comes from:

1. **RDAP**, at the server the [IANA bootstrap](https://data.iana.org/rdap/dns.json)
   lists for the TLD. Every gTLD has one, and so do many ccTLDs (`.uk`, `.fr`,
   `.nl`, `.pl`, ...).
2. **WHOIS**, only for a TLD with no RDAP service, at the server IANA names
   for it. This matters more than it sounds: `.it`, `.eu`, `.de`, `.es`,
   `.ch`, `.at`, `.io` and `.co` have no RDAP in the bootstrap.

| `status` | Meaning |
|---|---|
| `ok` | registered, and the registry published the expiry date |
| `not_published` | registered, but the registry does not publish an expiry date. DENIC (`.de`) and EURid (`.eu`) are the common cases. |
| `not_registered` | the registry says the name does not exist |
| `unavailable` | no answer this time (timeout, rate limit, unreadable reply). `error` says which. A known expiry is kept rather than erased. |

A date is shown only when a registry published it. `not_published` is an
answer, not a gap: it is never replaced by an estimate. A WHOIS reply whose
expiry field is in a form CertMate does not recognise is `unavailable`, not a
guess.

```jsonc
{
  "domain_registration": {
    "enabled": true,              // opt-in, like the rest of discovery
    "include_inventory": true,    // also follow domains discovery found
    "extra_domains": ["brand.it"]
  }
}
```

**When it runs.** Daily at 06:00, after discovery and the CT poll, and on
**Scan now**. Registries rate-limit, and some answer a burst with a temporary
ban, so a sweep:

- asks at most 100 registries, one second apart;
- asks a domain again only when its answer is due: daily within 60 days of
  expiry, weekly otherwise, and after 6 hours when the last lookup failed.

A large estate is therefore covered over a few days, not in one burst.

**Network.** RDAP goes over HTTPS and honours `HTTPS_PROXY`. WHOIS is a raw
TCP connection to port 43. It cannot go through an HTTP proxy, and it is
refused for private and loopback addresses by the same SSRF guard as the probe.
On a host that reaches the internet only through a proxy, the TLDs without
RDAP come back `unavailable`.

The **Domain registrations** panel on `/inventory` lists them, soonest expiry
first, with the registrar and whether the answer came over RDAP or WHOIS.

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
| GET | `/api/inventory/domains` | viewer | Domain registration expiry, soonest first (since API contract 2.6) |
| GET | `/api/inventory/<fingerprint>/adopt` | viewer | Adoption plan (feasibility + pre-fill) |
| POST | `/api/inventory/<fingerprint>/adopt` | operator | Adopt & manage the certificate |
| DELETE | `/api/inventory/<fingerprint>` | operator | Forget a record (the certificate itself is untouched) |

### Forgetting a record

`DELETE /api/inventory/<fingerprint>` removes a certificate and every endpoint
observed for it. The certificate itself is not touched — CertMate only forgets
that it saw it — so this is how you clean up after a mistaken scan, a
decommissioned host, or a name that was never yours. The **Forget** button on
each inventory row does the same thing.

It forgets an observation; it is not a blocklist. If the domain is still in the
discovery configuration the certificate will be recorded again on the next
sweep, so remove it from **Discovery configuration** first when the intent is
"stop looking at this".

---

## Security model

- **Opt-in.** `monitored_endpoints` and `ct_monitoring` both default to
  `enabled: false`. Nothing probes or polls until you turn it on.
- **SSRF guard.** The probe resolves a target first and refuses private,
  loopback, link-local, reserved, multicast, CGNAT (`100.64.0.0/10`) and any
  other non-globally-routable address — including IPv4-mapped IPv6 — unless
  `allow_private` is set. The validated IP is pinned for the connection with SNI
  set to the hostname, so a DNS rebind between the check and the handshake cannot
  redirect the probe to an internal host. The OCSP, CRL and issuer URLs a
  certificate names are fetched through the same guard.
- **Domain scope.** A scoped API key only sees inventory records within its
  `allowed_domains`, the same boundary the certificate API enforces.
- **CSV safety.** Certificate fields come from untrusted (probed / CT-logged)
  certificates; CSV export neutralises spreadsheet formula-injection leads.
- **Failure isolation.** Every sweep/poll is failure-isolated per item, so
  discovery can never stall or abort a certificate operation.
