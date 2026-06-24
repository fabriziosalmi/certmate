# Deployment Probes

Probes verify that your certificates are reachable on the network by performing a live TLS handshake against the deployed server.

## Configuration

Configure probes per-domain in **Settings → Deployment Probes**.

| Field | Description |
|---|---|
| Domain | The certificate domain to probe |
| Port | TCP port (default: 443 for HTTPS/TLS, 587 for SMTP STARTTLS) |
| Protocol | `HTTPS/TLS` — standard HTTPS handshake, `TLS` — raw TLS without HTTP, `SMTP STARTTLS` — plain SMTP upgraded to TLS |

Protocol and port are stored in the certificate's `metadata.json` under `deployment_protocol` and `deployment_port`.

## How probing works

### Backend probe

1. The backend reads the configured port and protocol from the certificate metadata.
2. A socket connection is opened and a TLS handshake is performed.
3. The served certificate fingerprint is compared to the local stored certificate.
4. The result (reachable, deployed, certificate_match) is cached for 5 minutes (configurable).

### Browser fallback

When the backend probe reports the server as unreachable **and** the protocol is `HTTPS/TLS`, a browser-side fallback is triggered via `fetch(..., { mode: 'no-cors' })`. This can verify reachability even when the backend cannot connect (e.g. network segmentation).

For `TLS` and `SMTP STARTTLS` protocols, the browser fallback is **skipped** because browsers cannot perform raw TLS or SMTP connections. The browser status shows "Not Checked".

### Cache

| Layer | TTL | Bypass |
|---|---|---|
| Backend (memory) | 300 s (default) | `?refresh=1` query parameter |
| Frontend (memory) | 300 s | `forceRefresh=true` (Check Probe button) |

## API

### Check deployment status

```
GET /api/certificates/<domain>/deployment-status
GET /api/certificates/<domain>/deployment-status?refresh=1
```

Returns:

| Field | Type | Description |
|---|---|---|
| domain | string | The probed domain |
| deployed | boolean | Whether a certificate was served |
| reachable | boolean | Whether the server responded |
| certificate_match | boolean/null | Whether the served cert matches the stored one |
| method | string | Protocol used (`https-tls`, `tls`, `smtp-starttls`) |
| port | integer | TCP port probed |
| protocol | string | Same as method |
| error | string | Error message if the probe failed |
| browser | object | Browser fallback result (HTTPS only) |

### Configure probe

```
PATCH /api/certificates/<domain>
```

```json
{ "deployment_port": 444, "deployment_protocol": "https-tls" }
```

Set to `null` to remove the probe configuration:

```json
{ "deployment_port": null, "deployment_protocol": null }
```
