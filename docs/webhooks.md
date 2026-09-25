# Generic webhooks

CertMate's notification channels (Settings → Notifications) include a
**generic webhook**: an HTTP request CertMate sends to a URL of yours on
certificate lifecycle events. Slack, Discord, Google Chat, Telegram, ntfy and Gotify have
their own channel types; the generic one is for everything else — Mattermost,
PagerDuty, an ITSM endpoint, your own service.

## Events

`certificate_created`, `certificate_renewed`, `certificate_expiring`,
`certificate_revoked`, `certificate_failed`, `certificate_deployed`,
`domain_expiring`, `deploy_hook_failed`, `certificate_deploy_incomplete`.

Two event lists narrow what is sent, and an empty list means every event: the
global **Notify on Events** list (`notifications.events`) applies to every
channel, email included, and each webhook can then be limited further by its
own list. The settings page offers seven events for both lists:
`certificate_created`, `certificate_renewed`, `certificate_deployed`,
`certificate_expiring`, `certificate_revoked`, `certificate_failed` and
`domain_expiring` — every event that can be filtered on.

`deploy_hook_failed` and `certificate_deploy_incomplete` are delivered whatever
the filter says: they report a failure an operator must not be able to silence
by accident.

### The two expiry warnings

| Event | When |
|---|---|
| `certificate_expiring` | a managed certificate is at 14, 7, 3 or 1 days, or has expired. With auto-renew off the first warning comes at the renewal threshold instead, because nothing else is going to act. |
| `domain_expiring` | a tracked domain *registration* is at 60, 30, 14, 7 or 1 days, or has expired ([registration expiry](discovery-inventory.md#domain-registration-expiry)). |

Each threshold is announced **once per expiry date**: a renewed certificate
starts again from the first threshold, and an unfixed one is announced at each
mark rather than every morning. Both carry `days_left`, `days_until_expiry`,
`expires_at`, `expired` and `threshold_days` in `details`; `certificate_expiring`
adds `auto_renew`, and `domain_expiring` adds `registrar` and `source`.

## Google Chat

Create an [incoming webhook in a Google Chat space](https://developers.google.com/workspace/chat/quickstart/webhooks),
then in **Settings → Notifications → Webhooks** add a webhook, choose **Google Chat**,
and paste the URL copied from that space (`https://chat.googleapis.com/...?...`).
Optionally set **CertMate URL** to the HTTPS address your Chat users open in a
browser (for example, `https://certmate.example.com`). Leave it empty to send
and test the card without buttons.
Enable notifications and the webhook, select events if desired, save, and use
**Test** to send a sample card. No OAuth credentials or Google Cloud project
are needed for an incoming webhook. The webhook can post only into its own
space; it cannot receive replies or run interactive actions.

CertMate sends a single Google Chat [`cardsV2`](https://developers.google.com/workspace/chat/api/reference/rest/v1/cards) message with a title, event status,
summary and certificate details. When CertMate URL is configured, the card has
**Open CertMate** and, for certificate events with a domain, **View certificate** buttons that open the
dashboard's certificate detail panel (`/?cert=<domain>`). No separate text
message is sent.
It uses the same event filters, delivery attempts and delivery log as other
webhooks. Google Chat webhook URLs contain `key` and `token` query parameters:
the entire URL is masked when settings are read back, preserved on an
unrelated save, and reduced to `https://chat.googleapis.com` in delivery logs.
Only HTTPS incoming webhook URLs at `chat.googleapis.com` are accepted for
this channel. Invalid Google Chat destinations (or an invalid optional
CertMate URL) are rejected when settings are saved, before an event fires;
the same validation runs at send time. Google Chat applies a per-space message
rate limit, so a burst may be retried after HTTP 429.

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
| `{{cert}}` | the leaf certificate, PEM |
| `{{fullchain}}` | the leaf certificate plus its chain, PEM |

### Sending the certificate itself

`{{cert}}` and `{{fullchain}}` are different from the rest: every other
placeholder comes out of the event, and these two are read from disk when the
delivery happens. That is deliberate — an event travels to every subscriber,
and a certificate has no business being handed to listeners that did not ask
for one. Nothing is read unless the template being rendered names it.

They let a webhook *deliver* a renewal rather than announce it:

```json
{"domain": "{{domain}}", "chain": "{{fullchain}}", "renewed_at": "{{timestamp}}"}
```

Both render **empty** when the event names no domain, or names one this
instance does not hold — a `test` delivery included, since it is about no
certificate. A certificate and its chain are public material: they are what
the server presents in every handshake, so this sends nothing an observer
could not already collect.

**The private key is not a placeholder.** `{{privkey}}` renders as an unknown
name, and the key file is never opened. Whether the key should travel in the
same request as the certificate — and under which conditions — is the open
question in [#218](https://github.com/fabriziosalmi/certmate/issues/218). To
deliver a key today, use a deploy hook, which runs on the machine that needs
it and never puts the key in a request body.

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
body. **Test** sends one real request with the event name `test`: a single
attempt, no retries, and no entry in the delivery log.

## Method, authentication, timeout, attempts

| Setting | Values | Default |
|---|---|---|
| Method | `POST`, `PUT`, `PATCH` | `POST` |
| Authentication | none · **Bearer token** (`Authorization: Bearer …`) · **Basic** (username + password) · **Header** (a header name and value, e.g. `X-API-Key`) | none |
| Timeout | 1–60 s | 10 |
| Attempts | 1–5 (total deliveries, exponential backoff 1 s, 2 s, 4 s…); `0`, accepted from older configs, means 1 | 3 |

A failure that another attempt cannot change is not retried: a configuration
error (a missing or non-`http(s)` URL, a refused internal address) or an HTTP
4xx answer other than `408`, `425` and `429`. Timeouts, connection errors,
`5xx` and those three statuses are retried with the backoff above.

When the configuration is read back, the webhook URL, the bearer token, the
basic password, the header value, the HMAC secret and the value of **every**
custom header are masked as `********`, and preserved unchanged when the form
is saved without retyping them. Preview masks less: it shows the URL, and
masks only headers whose name contains `authorization`, `key`, `token`,
`secret` or `cookie`.

The delivery log records the webhook's name and type, the **origin** of its
URL, the event, the HTTP status, the number of attempts, the error and the
duration. It does not record headers, tokens, the basic password or the body.

Origin means scheme and host — `https://hooks.slack.com`, not the path after
it. For Slack, Discord, ntfy and Gotify that path *is* the credential, and the
log is a file that outlives the request and is read back through the API.
Which host a delivery went to is what the log is for; the rest of the URL is
not needed to answer that, and `Name` and `Type` already say which webhook it
was. Entries written by an older version are reduced the same way when they
are read.

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

## A worked example: deploying through an automation runner

A webhook is worth more than it looks when the receiver on the other end can
act. @tuxpowered built and
[shared a starter n8n workflow](https://share-n8n.com/shared/eFFBfVRU8uF5) that
takes the deploy-hook payload and pushes the certificate onward, and it is the
clearest answer anyone has given to "how do I get certificates onto hosts
without CertMate holding credentials for all of them" (#396).

The shape is worth understanding even if you use something other than n8n:

1. CertMate fires the webhook. It knows the runner's URL and nothing else.
2. The runner fetches the credentials it needs from a secrets store of its own.
   In that example it is OpenBao, so the only secret CertMate's receiver holds
   is the one for reaching the store.
3. The runner deploys, by SSH or an API or whatever the target speaks.
4. Optionally a second listener lets a host **ask** for its own certificate,
   authenticated with a per-domain key held in the same store.

The property that makes this worth the hop: **CertMate never holds a credential
for a host it deploys to**. A certificate manager that can reach every server
is a certificate manager worth attacking, and this inverts it. It is also why
running the hooks on CertMate itself, which is what deploy hooks do, is the
simpler option and not always the right one.

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
