# certmate-sdk

A thin, dependency-light Python client for the [CertMate](https://github.com/fabriziosalmi/certmate) REST API.

```python
from certmate import Client

with Client("https://certmate.example.com", token="...") as c:
    job = c.create_certificate("app.example.com", dns_provider="cloudflare", wait=True)
    for cert in c.list_certificates():
        print(cert.domain, cert.days_until_expiry, cert.has_expired())
    print(c.audit_verify()["ok"])
```

`base_url`/`token` fall back to `CERTMATE_URL` / `CERTMATE_TOKEN`. The only
runtime dependency is `httpx` — no server code, no certbot.

## Asking whether a certificate has expired

Use `cert.has_expired()`, not `cert.days_until_expiry <= 0`.

`days_until_expiry` is a whole number of days and rounds down, so a
certificate with 23 hours of life left reports `0`, and that comparison calls
it expired. CertMate's own dashboard did exactly that until server 2.32.2, and
on a private CA it was every certificate: step-ca issues 24-hour certificates
by default.

`has_expired()` returns the server's own answer on API contract 2.2 and later
(`cert.expired`, with `cert.seconds_left` beside it for the real remaining
life). Against an older server it returns what a day count can honestly
support: `True` below zero, `False` above it, and `None` on exactly zero,
which is the one day the number cannot tell apart. `None` also means the
server could not parse the certificate, which is neither expired nor fine.
