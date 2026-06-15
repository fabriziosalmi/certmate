# CertMate Model Context Protocol (MCP) Server

CertMate includes a built-in Model Context Protocol (MCP) server written in Node.js. This allows agentic AI assistants (such as Claude or Gemini) to securely inspect certificate statuses, trigger renewals, request diagnostics, and interact with the CertMate API directly.

## Capabilities & Tools

The CertMate MCP server exposes the following tools to AI assistants:

**Inventory & status**
1. **`certmate_list_certificates`** — Lists all certificates managed by the active CertMate instance (with expiry, status, domains).
2. **`certmate_get_certificate`** — Full detail for one domain: status, days until expiry, SANs, DNS/CA provider, auto-renew flag. Use it to decide whether a cert needs renewing.
3. **`certmate_get_activity`** — Recent activity/audit log, to diagnose what changed or failed.
4. **`certmate_diagnostics`** — Comprehensive, sanitized diagnostic snapshot.
5. **`certmate_get_settings`** — Global settings and configuration.

**Lifecycle operations**
6. **`certmate_create_certificate`** — Requests a new TLS certificate for a domain (optional DNS provider, account, CA). May return a `job_id` (HTTP 202) for async issuance.
7. **`certmate_renew_certificate`** — Forces renewal of an existing certificate (may also return a `job_id`).
8. **`certmate_get_job`** — Polls an async create/renew job by `job_id` until it reports completed or failed.
9. **`certmate_set_auto_renew`** — Enables or disables automatic renewal for a single domain.
10. **`certmate_deploy_certificate`** — Manually executes all configured deployment hooks for a domain.
11. **`certmate_download_certificate`** — Returns a domain's certificate material as JSON (fullchain, key, chain) so an agent can deploy it elsewhere.

**Providers**
12. **`certmate_list_dns_providers`** — DNS providers supported and configured on this instance.
13. **`certmate_list_dns_accounts`** — Configured DNS provider accounts (credentials masked); use a returned account id as `account_id` when creating a certificate.

## Setup & Configuration

### Prerequisites
- Node.js (v18 or higher)
- npm

### Installation
Navigate to the `mcp/` directory in the CertMate repository and install the dependencies:
```bash
cd mcp
npm install
```

### Environment Variables
The MCP server communicates with the CertMate REST API and requires two environment variables:
- `CERTMATE_URL` — The URL of your CertMate instance (default: `http://localhost:8000`).
- `CERTMATE_TOKEN` — A valid API Bearer token with appropriate role permissions (typically `operator` or `admin`).

### Integration Example (Claude Desktop Config)
To add the CertMate MCP server to Claude Desktop, add the following to your configuration file (usually located at `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "certmate": {
      "command": "node",
      "args": ["/absolute/path/to/certmate/mcp/index.js"],
      "env": {
        "CERTMATE_URL": "http://localhost:8000",
        "CERTMATE_TOKEN": "your_secure_bearer_token"
      }
    }
  }
}
```

### Other MCP clients (Gemini, etc.)

The server speaks plain MCP over stdio, so any client that supports MCP works the
same way: point it at `node /absolute/path/to/certmate/mcp/index.js` and set the
two environment variables. Nothing in the server is Claude-specific.

## Operating CertMate with an AI agent (scheduled jobs)

Most top-tier assistants now support **scheduled tasks** (Claude, Gemini, and
others). Combine that with this MCP server and you get a hands-off "certificate
keeper": you describe the policy in plain language with explicit conditions, the
model schedules itself, and on each run it uses the tools above to enforce the
policy. The pattern is model-agnostic — anything that can run a saved prompt on a
schedule and call MCP tools will work.

### The loop the agent runs

1. `certmate_list_certificates` (or `certmate_get_certificate` per domain) to read `days_left` / status.
2. Decide per your condition, e.g. *renew when `days_left < 14`*.
3. `certmate_renew_certificate` for each due domain.
4. If a renewal returns a `job_id`, `certmate_get_job` until it reports `completed` / `failed`.
5. On failure, surface it — and CertMate's own notification channels (email, Slack, Discord, Telegram, ntfy, Gotify) will also fire on `certificate_failed`, so you get a push regardless.

### Example scheduled prompts

> **Daily, 08:00** — "Using the CertMate MCP tools, list all certificates. For any
> with `days_left < 14`, call `certmate_renew_certificate`, then poll
> `certmate_get_job` until done. Reply with a one-line summary per domain and call
> out any failures."

> **Weekly** — "Call `certmate_get_activity` and `certmate_diagnostics`. Summarize
> anything unusual (failed renewals, expired certs, scheduler not running) in three
> bullets. If nothing is wrong, say so."

> **On demand** — "Issue a cert for `shop.example.com` using `certmate_list_dns_providers`
> to pick a configured provider and `certmate_list_dns_accounts` for the account id,
> then watch the job to completion."

Because the conditions live in the prompt, you can tune the policy (threshold,
which domains, what to do on failure) without touching any code. Give the agent a
token scoped to exactly what it should do — `operator` for renew/deploy, `admin`
only if it must change settings or read diagnostics.

## Security

1. **Token Protection** — The MCP server requires a valid `CERTMATE_TOKEN`. It passes this token securely in the `Authorization` header for all requests to the CertMate API.
2. **Least privilege** — Scope the token to what the agent needs. A scheduled renew-keeper needs `operator`; reserve `admin` tokens for agents that must change settings or pull diagnostics. Revoke the token to instantly cut the agent off.
3. **Log Sanitization Compatibility** — Tools like `certmate_diagnostics` retrieve data after the Log Sanitizer has stripped sensitive credentials, protecting keys and tokens from leaking into LLM contexts.
