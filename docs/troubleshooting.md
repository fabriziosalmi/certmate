# Troubleshooting

Fixes for the failures reported most often, how to turn on debug logging, and what to include in a bug report.

## Common Issues & Solutions

### Certificate Creation Failures

**Issue**: `Certificate creation failed: ...` with a DNS-01 challenge error (the text after the prefix is certbot's own)
```bash
# Check DNS propagation
dig TXT _acme-challenge.example.com @8.8.8.8

# Verify DNS provider credentials
curl -H "Authorization: Bearer cf_token" \
 "https://api.cloudflare.com/client/v4/user/tokens/verify"
```

**Issue**: `Rate limit exceeded`
```bash
# Let's Encrypt rate limits:
# - 50 certificates per registered domain per week
# - 5 duplicate certificates per week
# - 300 new orders per account per 3 hours

# Check rate limit status
curl "https://crt.sh/?q=example.com&output=json" | jq length
```

**Issue**: `Permission denied accessing certificate files`
```bash
# Fix file permissions
sudo chown -R certmate:certmate /opt/certmate/certificates
sudo chmod -R 700 /opt/certmate/certificates
sudo chmod 600 /opt/certmate/certificates/*/privkey.pem
```

### API Authentication Issues

**Issue**: `401 Unauthorized`
```bash
# Verify token format
curl -H "Authorization: Bearer your_token_here" \
 http://localhost:8000/api/certificates

# The token cannot be read back: settings.json stores only an HMAC of it
# (api_bearer_token_hash). Compare against what you set in API_BEARER_TOKEN
# or API_BEARER_TOKEN_FILE.
```

**Issue**: lost or forgotten API token
```bash
# Set a new token and restart: at startup, the token from API_BEARER_TOKEN
# (or API_BEARER_TOKEN_FILE) replaces the stored one.
# (32+ characters; a malformed token is ignored and the old one stays.)
openssl rand -hex 32   # put the output in .env as API_BEARER_TOKEN=...
docker-compose up -d --force-recreate certmate
```

### Docker & Container Issues

**Issue**: `Container won't start`
```bash
# Check logs
docker-compose logs certmate

# Verify environment variables
docker-compose config

# Check port conflicts
netstat -tulpn | grep :8000
```

**Issue**: `Volume mount issues`
```bash
# Fix volume permissions
sudo chown -R 1000:1000 ./certificates ./data ./logs

# Check volume mounts
docker inspect certmate | jq '.[0].Mounts'
```

### Deployment Status Shows "Backend: Unreachable"

**Q: All my certificates show "Backend: Unreachable" even though they are issued, served, and downloadable. Is something broken?**

No. The deployment-status badge is an optional health indicator — it does not affect issuance, renewal, or download. CertMate's own process opens a TLS connection to `<domain>:<port>` and compares the served certificate's fingerprint against the stored one. The badge only answers whether CertMate itself can reach the service and see the expected certificate.

- **Deployed** — handshake succeeded and the fingerprint matches.
- **Wrong Cert** — handshake succeeded but a different certificate is served.
- **Unreachable** — CertMate could not open a TLS connection to the domain at all.

**Configuring the probe per certificate**

By default the probe connects on port 443 with a direct TLS handshake (HTTPS). You can change the port and protocol per certificate via the API or the dashboard:

| Protocol | Port (default) | Use case |
|---|---|---|
| `https-tls` | 443 | Standard HTTPS |
| `tls` | 465 | SMTPS, IMAPS, or any direct TLS service |
| `smtp-starttls` | 587 | SMTP with STARTTLS (port 25 also works) |

From the **dashboard**, open a certificate's detail panel and click **Configure Probe**, then enter the port and protocol.

From the **API**:

```bash
# Set probe to SMTP STARTTLS on port 587
curl -X PATCH https://certmate.example.com/api/certificates/example.com \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"deployment_port": 587, "deployment_protocol": "smtp-starttls"}'

# Reset to defaults (HTTPS on port 443)
curl -X PATCH https://certmate.example.com/api/certificates/example.com \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"deployment_port": null, "deployment_protocol": "https-tls"}'
```

The probe protocol defaults to the global timeout (3s) and can be tuned via the `CERTMATE_TLS_PROBE_TIMEOUT_SECONDS` environment variable.

**Global timeout tuning:**

```bash
# Accepts 1–30 seconds; default is 3
CERTMATE_TLS_PROBE_TIMEOUT_SECONDS=10
```

**"Unreachable" for every certificate** is common in Kubernetes/ingress setups where the CertMate pod cannot dial the public/ingress IP directly (split-horizon DNS, an egress `NetworkPolicy`, or TLS terminated by an ingress controller / load balancer). If the target is merely slow, raise the probe budget or configure the port/protocol to match your topology.

See [kubernetes.md](./kubernetes.md#deployment-status-badge-shows-backend-unreachable) for the Kubernetes-specific note. (Reference: [#263](https://github.com/fabriziosalmi/certmate/issues/263).)

### DNS Provider Specific Issues

**Cloudflare**:
```bash
# Verify API token permissions
curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
 -H "Authorization: Bearer your_token_here"

# Check zone access
curl -X GET "https://api.cloudflare.com/client/v4/zones" \
 -H "Authorization: Bearer your_token_here"
```

**AWS Route53**:
```bash
# Test AWS credentials
aws sts get-caller-identity

# Check Route53 permissions
aws route53 list-hosted-zones
```

**Azure DNS**:
```bash
# Verify service principal
az login --service-principal \
 -u $AZURE_CLIENT_ID \
 -p $AZURE_CLIENT_SECRET \
 --tenant $AZURE_TENANT_ID

# Check DNS zone access
az network dns zone list
```

## Debug Mode

Enable debug logging for troubleshooting:

```bash
# Docker / gunicorn: CERTMATE_LOG_LEVEL. The stock docker-compose.yml does not
# pass it through, so add it under the certmate service's environment: and
# recreate the container
      - CERTMATE_LOG_LEVEL=DEBUG

# Development server: --log-level overrides CERTMATE_LOG_LEVEL (default INFO)
python app.py --debug --log-level DEBUG

# FLASK_ENV=production makes --debug refuse to start, by design
FLASK_ENV=development
```


## Reporting Bugs

CertMate ships an in-app bug reporter that produces an actionable issue with one click. When an action fails and you're signed in as admin, the error toast surfaces a **Report this issue** button. Clicking it:

1. Calls `GET /api/diagnostics/snapshot` (admin-only) to collect sanitised operational state — CertMate version, Python version, OS, scheduler status, certificate count, DNS provider name, CA name, challenge type, storage backend, disk free, and the last 5 audit-log entries with all identifiers (resource_id, user, IP address, details, error) stripped.
2. Merges the snapshot with browser-side context (user agent, current page, viewport, the specific error envelope `endpoint` / `status` / `code` / `message` / `hint`).
3. Formats the result as Markdown and copies it to your clipboard.
4. Opens `github.com/fabriziosalmi/certmate/issues/new?template=bug_report.md` with the title pre-filled as `[Bug] <status> <code> on <method> <endpoint>`.

Paste the clipboard contents into the issue body, edit if you want, submit. The flow is fully manual — nothing leaves the install without your explicit click, and you can read everything before submitting (it's right there in the textarea). If your browser blocks the clipboard write or pop-ups, the reporter falls back to a modal with the markdown in an editable textarea and a clickable GitHub link.

## Support Checklist (manual reporting)

If the in-app reporter is unavailable (you're not signed in as admin, or you hit the bug before reaching the UI), please provide:

- [ ] CertMate version/commit hash
- [ ] DNS provider being used
- [ ] Error messages from logs
- [ ] Steps to reproduce the issue
- [ ] Environment details (Docker, Python version, OS)

```bash
# Collect system information manually (equivalent of the in-app snapshot)
echo "=== CertMate Debug Info ==="
echo "Version: $(docker exec certmate python -c 'import modules; print(modules.__version__)')"
echo "Python: $(docker exec certmate python --version)"
echo "OS: $(docker exec certmate cat /etc/os-release | head -2)"
echo "Certbot: $(docker exec certmate certbot --version)"
echo "DNS Plugins: $(docker exec certmate certbot plugins 2>/dev/null | grep '^\* dns-')"
# DO NOT paste settings.json into a public issue: it contains credentials.
# The /api/diagnostics/snapshot endpoint leaves credentials out, but it keeps
# domain names in its log lines and the names of your DNS accounts. Read it
# before you paste it:
curl -sS -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/diagnostics/snapshot | jq .
```
