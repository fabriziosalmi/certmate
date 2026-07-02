# certmate-sdk

A thin, dependency-light Python client for the [CertMate](https://github.com/fabriziosalmi/certmate) REST API.

```python
from certmate import Client

with Client("https://certmate.example.com", token="...") as c:
    job = c.create_certificate("app.example.com", dns_provider="cloudflare", wait=True)
    for cert in c.list_certificates():
        print(cert.domain, cert.days_until_expiry)
    print(c.audit_verify()["ok"])
```

`base_url`/`token` fall back to `CERTMATE_URL` / `CERTMATE_TOKEN`. The only
runtime dependency is `httpx` — no server code, no certbot.
