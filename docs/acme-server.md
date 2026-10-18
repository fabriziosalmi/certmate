# ACME server

CertMate can be the ACME certificate authority for your internal names. certbot,
lego, acme.sh and cert-manager get certificates from it the way they get them
from Let's Encrypt, signed by a root of CertMate's own that you install in the
trust stores of the machines that connect to those names. Each client is
enrolled with an External Account Binding (EAB) key, and the key says which
names it may order.

It is off by default. It is not a public CA: nothing outside your trust stores
trusts its root.

This is a different root from the one that signs [client certificates](guide.md).
A machine that trusts one for server TLS does not trust the other for mTLS.

The API that administers it is in the [API reference](api.md#acme-server).

## Turning it on

1. **Serve CertMate over HTTPS.** ACME requires it (RFC 8555, section 6.1), so
   `/acme/` refuses plain HTTP. The clients must trust the certificate of the
   address they reach. That is the certificate of CertMate's own front, not the
   ACME root. Behind a proxy that ends TLS, set `BEHIND_PROXY=true`, so a
   request keeps the scheme the client used (see
   [behind a reverse proxy](installation.md#behind-a-reverse-proxy)). For a
   lab, **Also over plain HTTP** turns the refusal off.
2. **Settings → ACME → Serve ACME.** While it is off, every `/acme/` address
   answers 404.
3. **Install the root.** Download it from the link next to the directory URL,
   or from `/acme/root`, and add it to the trust stores of the machines that
   will connect to the certificates' names. It is made the first time it is
   needed: RSA 4096, valid ten years, named `CertMate ACME CA` and six hex
   digits, so two instances' roots are told apart in a trust store.
4. **Create an EAB key** under **New EAB key**, with the names it may order.
   Its HMAC key is shown once, with the commands for certbot, lego, acme.sh and
   cert-manager filled in. Copy it, then press **I have copied it**.
5. **Give the client the directory URL**, `https://<host>/acme/directory`. The
   settings page shows it as built from the address you reached CertMate at.
   Give clients the one they will reach.

## The names each client may order

An EAB key carries the patterns its accounts' orders are held to:

| Pattern | Allows |
| --- | --- |
| `nas.lab.internal` | that name only |
| `*.lab.internal` | every name below `lab.internal`, at any depth, and not `lab.internal` itself |

Every name of an order must match a pattern of the key that enrolled the
account, or the order is refused with `rejectedIdentifier` before anything is
fetched. A wildcard certificate name `*.B` is allowed by a `*.` pattern at or
above `B`: `*.lab.internal` allows `*.team.lab.internal` and `*.lab.internal`
itself. An exact name never allows a wildcard.

Disabling an EAB key stops it enrolling new accounts. The accounts it enrolled
keep ordering within its names. To stop one account, deactivate it under
**Accounts**.

**Require an EAB key** is on by default. Turned off, anyone who reaches
`/acme/` can create an account, and such an account may order the names under
**Names an account without an EAB key may order**. That list is empty by
default, so those accounts order nothing.

## Proving control of a name

Each order proves each of its names again. An authorization is not reused from
an earlier order.

**http-01.** The client serves a token at
`http://<name>/.well-known/acme-challenge/<token>`, and CertMate fetches it. So
CertMate must reach the name on port 80. The fetch is the one place where the
server reaches into the network on a client's behalf, so it is guarded:

- Private networks are allowed, since internal names live there. Loopback,
  link-local, unspecified and multicast addresses, and the cloud metadata
  addresses, are refused, for the name and for every redirect. The connection
  goes to the address that was checked.
- It follows up to 5 redirects, to http or https on ports 80 or 443 only. An
  https hop is not verified, because the certificate it presents may be the
  one being replaced.
- It takes at most 10 seconds and reads at most 8 KiB. The check runs inside
  the client's request to the challenge, which answers with the result.

**dns-01.** The client publishes a TXT record at `_acme-challenge.<name>`.
CertMate asks the resolver it is configured with, with no cache, and follows
CNAMEs. That is how a [DNS alias](dns-providers.md) delegates the record to a
zone the client can write. The resolver is the one under **DNS resolvers** in
the inventory configuration (`dns_resolver.nameservers`, or
`CERTMATE_DNS_RESOLVERS`; see [discovery and inventory](discovery-inventory.md)).
With none set, it is the system's.

**Wildcards** are proved with dns-01 only, on the base name.

Not supported: tls-alpn-01, and IP address identifiers.

## The certificates

- **Signed by the root directly.** The chain a client downloads is the leaf
  alone. The root is in the trust stores, and a TLS server need not send it.
- **Built from the order, not copied from the CSR.** They carry the order's
  names, a subject of the first of them, server authentication as their only
  extended key usage, and the key usage the key type calls for. The CSR's key
  must be RSA of 2048 to 8192 bits, or EC on P-256 or P-384.
- **Valid 45 days by default**, from 1 to 365 under **Certificate validity**.
  A change applies to the certificates issued from then on.

### Why 45 days

The clients decide when they renew. Measured with the harnesses in
`tests/interop/`, or read in the client's code where noted:

| Client | Renews | At 45 days |
| --- | --- | --- |
| certbot 5.8.0 (read in its code) | with a third of the lifetime left | 15 days left |
| lego 5.5.2 | with a third of the lifetime left | 15 days left |
| acme.sh 3.1.5 | 29 days after issuance, unless given `--days` | 16 days left |
| cert-manager v1.21.2 | with a third of the duration left | 15 days left |

At 29 days or less, acme.sh renews when the certificate expires or after.
Give it a negative `--days`, which counts back from expiry: `--days -15`
renews with 15 days left. The command the settings page shows carries one when
the validity is under 45 days.

## Renewal information

The server answers ACME Renewal Information (RFC 9773). For each certificate it
suggests renewing between two thirds and five sixths of its lifetime (days 30
to 37.5 at the default 45), and at once when it has been revoked. A client
that reads it replaces a revoked certificate on its next run, with nobody
touching it.
certbot's ACME library picks its moment inside that window, measured in the
test suite.

A new order may name the certificate it `replaces`. It must be one the
account was issued, and not replaced already by another order that has not
failed.

## Revocation

A certificate is revoked by the account that ordered it, or with the
certificate's own key, through the client, as lego and acme.sh did in the
interoperability runs. An admin revokes it from the dashboard's **ACME** view.
The reasons accepted are the RFC 5280 codes 0 (unspecified), 1
(keyCompromise), 3 (affiliationChanged), 4 (superseded) and 5
(cessationOfOperation).

The certificates carry no CRL distribution point and no OCSP address. A relying
party that must check revocation fetches `/acme/crl` itself: DER, signed by the
root, made again after each revocation and at least hourly, with a next update
seven days on.

## What it issued, and to whom

The dashboard's **ACME** view, next to Server and Client, lists every
certificate the server issued, newest first: its names, status (valid, expired
or revoked), the account that ordered it and the EAB key that enrolled that
account. A viewer may read it; only an admin revokes.

**Settings → ACME** lists the EAB keys with how many accounts each enrolled,
and the accounts with how many orders and certificates each has. Deactivating
an account stops it for good. The certificates it already has stay valid;
revoke them one by one if they must not.

What an admin changes (options, keys, revocations, deactivations) is in the
[audit log](compliance.md). What the clients do is in the ACME server's own
database, which those lists read.

## Rate limit

Each client address may make 300 requests a minute to `/acme/`. lego
registered and got a certificate in 8 requests and acme.sh in 11, so that is
some 27 certificates a minute from one address. Over it, the client gets the
ACME problem `rateLimited` with `429` and `Retry-After: 60`. A fleet behind
one address that starts all at once, cert-manager in a cluster for instance,
can raise it under **Settings → API Keys → API Rate Limits** (`acme`), where
the switch that turns the API's rate limits off turns this one off too.

## Client commands

The settings page fills these in when it creates a key. With placeholders:

```bash
certbot certonly --standalone \
  --server https://<host>/acme/directory \
  --eab-kid <kid> --eab-hmac-key <hmac> \
  --email ops@example.internal --agree-tos \
  -d host.lab.internal
```

```bash
lego run --server https://<host>/acme/directory \
  --eab --eab.kid <kid> --eab.hmac <hmac> \
  --email ops@example.internal --accept-tos \
  --domains host.lab.internal --http
```

```bash
acme.sh --register-account --server https://<host>/acme/directory \
  --eab-kid <kid> --eab-hmac-key <hmac> -m ops@example.internal
acme.sh --issue --standalone --server https://<host>/acme/directory -d host.lab.internal
```

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: certmate-eab
  namespace: cert-manager
stringData:
  secret: <hmac>
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: certmate
spec:
  acme:
    server: https://<host>/acme/directory
    email: ops@example.internal
    privateKeySecretRef:
      name: certmate-acme-account
    externalAccountBinding:
      keyID: <kid>
      keySecretRef:
        name: certmate-eab
        key: secret
    solvers:
      - http01:
          ingress:
            ingressClassName: nginx
```

The lego, acme.sh and cert-manager forms are the ones the interoperability
runs used against this server, cert-manager there as an Issuer, which takes the
same spec. certbot's ACME library runs in the test suite. Its command line uses
the flags certbot documents and was not run end to end.

When CertMate's own certificate is not one the client trusts already, give the
client the certificate of CertMate's front: `LEGO_CA_CERTIFICATES` for lego,
`--ca-bundle` for acme.sh, and `caBundle` under `spec.acme` for cert-manager.
These are the ones the runs used.

## Backups

The ACME server's options and EAB keys are in the settings, and its database
(accounts, orders, certificates) and its CA in `data/acme/`.
[Backups](backup.md) carry all of them.

A share-safe backup carries the root without its key, and masks each EAB key's
HMAC key:

- **Restored onto the same instance**, the HMAC keys on disk are kept.
- **Restored onto another instance**, the EAB keys come back without them and
  enrol no one: create new keys and give them to the clients. The accounts
  already enrolled keep working, since an account needs its key only to
  enrol. When a client tries one of those keys, the log names it.
- **Without `ca.key`**, the server issues nothing and serves no root until it
  is put back from a full backup, with no restart needed. It never makes a new
  root over the one the clients trust.
