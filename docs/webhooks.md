# Generic webhooks

CertMate's notification channels (Settings → Notifications) include a
**generic webhook**: an HTTP request CertMate sends to a URL of yours on
certificate lifecycle events. Slack, Discord, Telegram, ntfy and Gotify have
their own channel types; the generic one is for everything else — Mattermost,
PagerDuty, an ITSM endpoint, your own service.

## Events

`certificate_created`, `certificate_renewed`, `certificate_expiring`,
`certificate_revoked`, `certificate_failed`, `certificate_deployed`,
`deploy_hook_failed`. Each webhook can be limited to a subset (leave the list
empty for all).

## The default body

With no template configured, the body is:

```json
{
  "event": "certificate_renewed",
  "title": "Certificate Renewed",
  "message": "Certificate Renewed: shop.example.com",
  "details": {"domain": "shop.example.com", "...": "whatever the event carries"},
  "timestamp": "2026-08-21T07:00:00Z"
}
```

## Payload template

Most receivers want their own shape. A **payload template** is JSON text with
`{{placeholders}}`, rendered per event:

```json
{"text": "{{title}}: {{domain}} ({{event}})", "days_left": {{details.days_until_expiry}}}
```

| Placeholder | Value |
|---|---|
| `{{event}}` | event name |
| `{{title}}` | human title, e.g. *Certificate Renewed* |
| `{{message}}` | one-line message |
| `{{timestamp}}` | ISO-8601 UTC |
| `{{domain}}` | the certificate domain (shortcut for `details.domain`) |
| `{{details}}` | the whole event payload as a JSON object |
| `{{details.<field>}}` | one field of it — `details.error`, `details.days_until_expiry`, `details.expires_at`, `details.hook_name`… |

Two rules keep a template valid JSON whatever the values are:

- **Inside a string** (`"text": "{{domain}} renewed"`) the value is inserted
  as an escaped string fragment. A value carrying quotes, newlines or
  backslashes cannot break out of the string.
- **Outside a string** (`"days": {{details.days_until_expiry}}`) the value is
  inserted as a JSON literal — a number, boolean, object, or a quoted string.

An unknown placeholder renders as an empty fragment inside a string and
`null` outside it. A template that does not render to valid JSON is rejected
when you save (HTTP 400 with the reason) — not discovered on the first
renewal.

**Preview** in the editor renders the request for a sample event without
sending it: method, URL, header names (credential values masked) and the
body. **Test** sends a real test event.

## Method, authentication, timeout, attempts

| Setting | Values | Default |
|---|---|---|
| Method | `POST`, `PUT`, `PATCH` | `POST` |
| Authentication | none · **Bearer token** (`Authorization: Bearer …`) · **Basic** (username + password) · **Header** (a header name and value, e.g. `X-API-Key`) | none |
| Timeout | 1–60 s | 10 |
| Attempts | 0–5 (total deliveries, exponential backoff 1 s, 2 s, 4 s…) | 3 |

Credentials — the bearer token, the basic password, the header value, and
any custom header whose name contains `authorization`, `key`, `token`,
`secret` or `cookie` — are masked as `********` when the configuration is
read back and preserved unchanged when the form is saved without retyping
them. They never appear in the delivery log.

## Signature

When the webhook has an **HMAC secret**, every request carries

```
X-CertMate-Signature: t=<unix-timestamp>,v1=<hex>
```

where `v1` is `HMAC-SHA256(secret, "<t>." + body)`. Verify it over the exact
raw body you received (the templated body, if you use one), and reject
timestamps older than a few minutes to stop replays:

```python
import hmac, hashlib, time
def verify(secret, header, body, max_age=300):
    parts = dict(p.split('=', 1) for p in header.split(','))
    if abs(time.time() - int(parts['t'])) > max_age:
        return False
    expected = hmac.new(secret.encode(), f"{parts['t']}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts['v1'])
```

## Outbound safety

The URL must be `http://` or `https://`. A host that resolves to a loopback,
private, link-local or otherwise non-public address is refused (SSRF guard)
unless the container runs with `CERTMATE_ALLOW_INTERNAL_WEBHOOKS=true` — set it
when your receiver genuinely lives on the internal network.

## API

- `GET/POST /api/notifications/config` — the notifications block, webhooks
  under `channels.webhooks` (admin).
- `POST /api/notifications/test` — `{"channel_type": "webhook", "config": {…}}`
  sends a test event through one webhook without saving it.
- `POST /api/notifications/webhook/preview` — `{"config": {…}, "event":
  "certificate_renewed"}` renders without sending; `400` with the reason when
  the config or template is invalid.
- `GET /api/webhooks/deliveries?limit=50` — recent deliveries (status,
  attempts, duration, error).
