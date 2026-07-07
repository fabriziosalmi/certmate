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

![CertMate CLI — the full SSL certificate lifecycle from the terminal](../demo/certmate-cli.gif)

## Quick start

```bash
pip install certmate-cli            # from PyPI (pulls in certmate-sdk)

export CERTMATE_URL=http://localhost:8000
export CERTMATE_TOKEN=...            # omit on a fresh (setup-mode) instance

certmate cert create app.example.com --dns cloudflare --wait
certmate cert ls
certmate cert info app.example.com
certmate cert renew app.example.com --force
certmate cert create app.example.com --dns cloudflare --dry-run   # validate, don't issue
certmate audit verify
```

Pass the token via `CERTMATE_TOKEN` (as above), not `--token`: command-line
arguments are visible to other local processes (`ps`) and land in shell
history. `--token` still works for compatibility, but the CLI warns when it is
used interactively.

## Server compatibility

The clients work against any CertMate v2.x server, with two features that
need v2.21.1+ (the server started reporting them in that release):

- `cert renew` outcome: v2.21.1+ returns `renewed: true/false`, so the CLI can
  say "renewed" vs "not due". Against older servers it reports neutrally that
  the server did not state the outcome (it never claims success it cannot know).
- `dns test <provider>` / `cert create --dry-run` without explicit credentials:
  v2.21.1+ falls back to the provider's stored account credentials on an empty
  config. Older servers reject the empty config with a clear error.

Working from a checkout instead? Install the in-repo copies editable:

```bash
pip install -e clients/certmate-sdk -e clients/certmate-cli
```

See [`demo/`](../demo/) for the recorded full-cycle run (real issuance, LE staging).
