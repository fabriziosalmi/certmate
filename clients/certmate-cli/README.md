# certmate-cli

The [CertMate](https://github.com/fabriziosalmi/certmate) SSL certificate
lifecycle from your terminal — built on `certmate-sdk`.

```bash
pip install certmate-cli
export CERTMATE_URL=http://localhost:8000
export CERTMATE_TOKEN=...

certmate cert create app.example.com --dns cloudflare --wait
certmate cert ls
certmate cert info app.example.com
certmate cert renew app.example.com --force
certmate cert create app.example.com --dns cloudflare --dry-run
certmate audit verify
```

Connection comes from `--url`/`--token` or `CERTMATE_URL`/`CERTMATE_TOKEN`.
Prefer the `CERTMATE_TOKEN` environment variable over `--token`: command-line
arguments are visible to other local processes (`ps`) and shell history.
