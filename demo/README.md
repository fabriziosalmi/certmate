# CertMate CLI demo

![CertMate CLI — the full SSL certificate lifecycle from the terminal](certmate-cli.gif)

The whole certificate lifecycle driven from the terminal by
[`certmate-cli`](../clients/certmate-cli) (`pip install certmate-cli`):

1. **`pip install certmate-cli`** — a real PyPI package (pulls in `certmate-sdk`)
2. **`certmate health`** — talk to a CertMate instance
3. **`certmate cert create demo.certmate.org --dns cloudflare --wait`** — issue a
   **real** certificate over DNS-01 and block until it is live
4. **`certmate cert ls` / `certmate cert info demo.certmate.org`** — it is really there
5. **`certmate audit verify`** — every action lands in a tamper-evident, signed audit chain

The issuance in the recording is real: DNS-01 via Cloudflare against Let's Encrypt
**staging** — so it is safe to re-run and does not spend production rate limits.

A crisper [`certmate-cli.mp4`](certmate-cli.mp4) is produced alongside the GIF.

## Reproduce

Recorded with [VHS](https://github.com/charmbracelet/vhs) from
[`certmate-cli.tape`](certmate-cli.tape):

```bash
# needs a CertMate instance reachable at $CERTMATE_URL
# (the tape points at http://localhost:18899 and issues against LE staging)
vhs demo/certmate-cli.tape        # writes certmate-cli.gif + certmate-cli.mp4
```

The tape pre-installs the CLI's dependencies into a throwaway virtualenv, so the
on-camera `pip install certmate-cli` is real yet fast.
