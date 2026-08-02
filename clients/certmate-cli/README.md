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

## Pulling certificates onto a host

`cert download` fetches one file at a time, so a target server can pull
exactly what it deploys instead of the certificate manager pushing to it:

```bash
certmate cert download app.example.com --file fullchain -o /etc/ssl/certs/app.pem
certmate cert download app.example.com --file privkey   -o /etc/ssl/private/app.key
```

Files are created **0600**, with the mode set at creation rather than after
the write, so the key is never briefly world-readable.

This is worth preferring over pushing when the manager would otherwise need
credentials on every target host. Give each host an API key scoped to its own
domain and run the pull on a timer: the host needs no inbound access, and the
manager holds no credentials for it. `cert`, `chain` and `fullchain` are
readable by a viewer-role key; `privkey`, `combined` and `pfx` need operator.

`--file privkey --key-format pkcs1` serves the legacy
`BEGIN RSA PRIVATE KEY` form for stacks that reject certbot's PKCS#8.
`--bundle zip` or `--bundle json` fetch the whole certificate instead, and
`-o -` writes to stdout.

Connection comes from `--url`/`--token` or `CERTMATE_URL`/`CERTMATE_TOKEN`.
Prefer the `CERTMATE_TOKEN` environment variable over `--token`: command-line
arguments are visible to other local processes (`ps`) and shell history.
