# CertMate clients

Terminal-facing clients for the CertMate REST API. Two independently
installable packages, layered so the CLI is built **on** the SDK (never the
reverse):

```
clients/
  certmate-sdk/   # `pip install certmate-sdk`  → from certmate import Client   (deps: httpx)
  certmate-cli/   # `pip install certmate-cli`  → the `certmate` command        (deps: certmate-sdk, typer, rich)
```

They live in-repo (not a separate repo) so a change to an endpoint and its
client verb ship in one PR, versioned and tested against the same server. The
packaging is split so `pip install certmate-sdk` stays light — it never pulls
certbot, DNS plugins, or cloud SDKs.

## Quick start

```bash
pip install -e clients/certmate-sdk -e clients/certmate-cli

export CERTMATE_URL=http://localhost:8000
export CERTMATE_TOKEN=...            # omit on a fresh (setup-mode) instance

certmate cert create app.example.com --dns cloudflare --wait
certmate cert ls
certmate cert info app.example.com
certmate cert renew app.example.com --force
certmate cert create app.example.com --dns cloudflare --dry-run   # validate, don't issue
certmate audit verify
```
