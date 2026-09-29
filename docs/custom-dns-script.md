# Custom DNS script

Some DNS providers have no certbot plugin and no `dns-lexicon` support. There
is nothing to install and nothing to configure, because nothing exists. The
`custom-script` provider is for those: you supply a script that creates the
`_acme-challenge` TXT record, and CertMate drives it through certbot's core
`--manual` mode.

This is a supported path, not a workaround. Renewals go through it too.

It is the answer for Total Uptime, Netriplex, Oracle Cloud DNS, an in-house
DNS server, a DDI appliance with its own API — anything where you can create
and delete a TXT record programmatically but nobody has written a plugin.

## Configuration

Settings → DNS Providers → **Custom Script (your own DNS hooks)**, or through
the API:

```json
{
  "dns_providers": {
    "custom-script": {
      "accounts": {
        "default": {
          "auth_hook": "/opt/certmate/hooks/totaluptime-auth.sh",
          "cleanup_hook": "/opt/certmate/hooks/totaluptime-cleanup.sh",
          "propagation_seconds": 120
        }
      }
    }
  }
}
```

| field | required | what it is |
| :--- | :--- | :--- |
| `auth_hook` | **yes** | absolute path to the script that creates the TXT record |
| `cleanup_hook` | no | absolute path to the script that removes it afterwards |
| `propagation_seconds` | no | passed to your scripts as an environment variable, not to certbot — see [Waiting is your script's job](#waiting-is-your-scripts-job) |

Like every other provider, `custom-script` supports more than one account, so
you can point different domains at different scripts.

CertMate runs certbot as:

```
certbot ... --manual --preferred-challenges dns \
            --manual-auth-hook /path/to/auth.sh \
            --manual-cleanup-hook /path/to/cleanup.sh
```

`--manual` is a certbot core feature, not an installable plugin, so the
plugin-installed preflight skips it. There is nothing to `pip install`.

## Path rules, and why they are strict

CertMate checks six things when the certificate is issued, and refuses with a
message naming the one that failed:

| the path must be | refused when |
| :--- | :--- |
| absolute | `hooks/auth.sh` |
| an existing file | the path is a directory, or nothing is there |
| executable | `chmod -x` |
| free of whitespace and shell metacharacters | `/opt/My Hooks/auth script.sh` |
| **not world-writable** | mode `0o002` set — `chmod 777` |
| **not group-writable** | mode `0o020` set — `chmod 775` |

The last two are a refusal, not advice: the script runs with CertMate's
privileges, so anyone who can rewrite it gets those privileges. A warning at
issuance time is advice nobody reads. `chmod 755` or stricter.

The whitespace rule is the surprising one, and it is not CertMate being fussy.
certbot executes manual hooks **through the shell**, and validates them by
splitting the command on whitespace. A path with a space in it cannot work
even when quoted — certbot fails with `HookCommandNotFound` on a truncated
token, which is a baffling message to receive about a file that plainly
exists. Refusing it up front is the difference between a clear error and an
afternoon.

So this works:

```
/opt/certmate/hooks/totaluptime-auth.sh
```

and this cannot, whatever you do to it:

```
/opt/My Hooks/auth script.sh
```

## The contract your script is called with

certbot puts these in the environment. Verified against certbot 2.10.0
(`certbot/_internal/plugins/manual.py`), which is the version CertMate pins:

| variable | auth hook | cleanup hook | what it holds |
| :--- | :---: | :---: | :--- |
| `CERTBOT_DOMAIN` | yes | yes | the domain being authenticated — **without** the `_acme-challenge.` prefix |
| `CERTBOT_VALIDATION` | yes | yes | the TXT record's value |
| `CERTBOT_ALL_DOMAINS` | yes | yes | every domain in this certificate, comma-separated |
| `CERTBOT_REMAINING_CHALLENGES` | yes | yes | how many challenges come after this one |
| `CERTBOT_AUTH_OUTPUT` | — | yes | whatever your auth hook printed to stdout |
| `CERTBOT_TOKEN` | — | — | **not set.** It is an HTTP-01 value, and certbot explicitly removes it for DNS-01 |
| `CERTMATE_DNS_PROPAGATION_SECONDS` | yes | yes | see below — this one is CertMate's, not certbot's |

`CERTBOT_AUTH_OUTPUT` is the intended way to hand something from the auth hook
to the cleanup hook — a record id, for instance, so cleanup deletes the record
it created rather than searching for one. Print it, and read it back.

Your script must create:

```
_acme-challenge.<CERTBOT_DOMAIN>   TXT   "<CERTBOT_VALIDATION>"
```

Exit non-zero to fail the challenge. Whatever you print goes into CertMate's
certbot log, so print enough to debug with and nothing you would not want in a
log file.

## Waiting is your script's job

`--manual` has no propagation flag. certbot does not sleep between calling your
hook and asking the CA to validate, so **if your script returns before the
record is visible, the challenge fails.**

Every other provider in CertMate has a propagation setting that becomes a
certbot flag. For `custom-script` there is no flag to set it on, so CertMate
exports the configured value to your script instead:

```bash
sleep "${CERTMATE_DNS_PROPAGATION_SECONDS:-60}"
```

The account-level `propagation_seconds` wins; when it is not set, the
provider-wide default is exported instead, so the variable is always present.

Sleeping is the simple answer. Polling your own authoritative nameservers
until the record appears is the better one, and it is usually faster.

## Wildcard and apex in one certificate

A certificate for `example.com` **and** `*.example.com` produces **two
challenges for the same `_acme-challenge.example.com` name**, with different
validation values, one after the other.

Both records must exist at the same time. A script that deletes the old record
before creating the new one will pass the first challenge and fail the second,
and the failure will look like a propagation problem.

`CERTBOT_REMAINING_CHALLENGES` is how you tell where you are: it is `0` on the
last challenge. If your cleanup has to run per-challenge rather than at the
end, that is the value to branch on.

## Renewal

Renewals work, without re-entering anything. Every renewal passes certbot the
hook paths and the propagation wait configured **now**, exactly as issuance
does, so moving a script only needs its new path in Settings. Nothing has to
be reissued.

Before v2.42.0 renewal relied on the paths certbot had recorded in the
certificate's renewal configuration at issue time, and a moved script kept
failing until the certificate was reissued.

## A worked example

Two scripts against a provider with a REST API. Adapt the two `curl` calls;
the shape is the same everywhere.

`/opt/certmate/hooks/dns-auth.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

API="https://api.example-dns.net/v1"
TOKEN="$(cat /etc/certmate/dns-api-token)"   # not in the script, not in settings

# Create the record. Print the id so the cleanup hook can delete exactly this one.
record_id=$(curl -fsS -X POST "$API/zones/example.com/records" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"type\":\"TXT\",\"name\":\"_acme-challenge.${CERTBOT_DOMAIN}\",\"value\":\"${CERTBOT_VALIDATION}\",\"ttl\":60}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

echo "$record_id"

# Wait until our own authoritative servers answer with it, up to the configured
# budget. Polling beats sleeping: it is usually faster and it fails loudly.
deadline=$(( SECONDS + ${CERTMATE_DNS_PROPAGATION_SECONDS:-60} ))
until dig +short "@ns1.example-dns.net" TXT "_acme-challenge.${CERTBOT_DOMAIN}" \
      | grep -qF "$CERTBOT_VALIDATION"; do
  (( SECONDS < deadline )) || { echo "TXT record did not appear in time" >&2; exit 1; }
  sleep 5
done
```

`/opt/certmate/hooks/dns-cleanup.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

API="https://api.example-dns.net/v1"
TOKEN="$(cat /etc/certmate/dns-api-token)"

# CERTBOT_AUTH_OUTPUT is what the auth hook printed: the record id.
record_id="${CERTBOT_AUTH_OUTPUT:-}"
[ -n "$record_id" ] || exit 0

curl -fsS -X DELETE "$API/zones/example.com/records/${record_id}" \
  -H "Authorization: Bearer $TOKEN"
```

Then:

```bash
chmod 700 /opt/certmate/hooks/dns-auth.sh /opt/certmate/hooks/dns-cleanup.sh
```

Test them before CertMate does, with the variables set by hand:

```bash
CERTBOT_DOMAIN=example.com CERTBOT_VALIDATION=test-value \
  /opt/certmate/hooks/dns-auth.sh
```

## Where the credentials go

Not in the script, and not in CertMate. The script is a path CertMate executes;
the API token your script needs belongs in a file your script reads, owned by
the user CertMate runs as and readable by nobody else.

CertMate never sees that token, which also means it cannot mask it: anything
your script prints to stdout ends up in the certbot log.

## Trust model

Hook scripts execute **with CertMate's privileges**, the same as deploy hooks.
The paths are configured by an authenticated admin, and the five path checks
exist to catch mistakes, not to contain a hostile administrator — someone who
can set `auth_hook` can already run code on the host.

CertMate enforces the two permission rules above — it will not execute a
world-writable or group-writable hook — but it cannot check the directory the
script sits in. Keep the scripts outside any directory an unprivileged user
can write to, because a writable directory means the file can be replaced.

## See also

- [DNS Providers](dns-providers.md) — the providers that need no script
- [Deploy hooks](deploy-hooks.md) — the other place CertMate runs your scripts,
  with the same trust model
