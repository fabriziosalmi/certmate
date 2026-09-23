# CertMate Model Context Protocol (MCP) Server

CertMate includes a built-in Model Context Protocol (MCP) server written in Node.js. This allows agentic AI assistants (such as Claude or Gemini) to inspect certificate statuses, trigger renewals, request diagnostics, and interact with the CertMate API directly.

## Capabilities & Tools

The CertMate MCP server exposes the following tools to AI assistants:

**Inventory & status**
1. **`certmate_list_certificates`** — Lists all certificates managed by the active CertMate instance (with expiry, status, domains).
2. **`certmate_get_certificate`** — Full detail for one domain: status, days until expiry, SANs, DNS/CA provider, auto-renew flag. Use it to decide whether a cert needs renewing.
3. **`certmate_get_activity`** — Recent activity/audit log, to diagnose what changed or failed.
4. **`certmate_diagnostics`** — Comprehensive, sanitized diagnostic snapshot.
5. **`certmate_get_settings`** — Global settings and configuration, with secret values masked.

**Lifecycle operations**
6. **`certmate_create_certificate`** — Requests a new TLS certificate for a domain (optional DNS provider, account, CA). The server always asks for async issuance, so this returns a `job_id` (HTTP 202) to poll.
7. **`certmate_renew_certificate`** — Forces renewal of an existing certificate. Also async: returns a `job_id`.
8. **`certmate_get_job`** — Polls an async create/renew/update job by `job_id` until its status is `succeeded` or `failed` (`queued` and `running` are not final).
9. **`certmate_set_auto_renew`** — Enables or disables automatic renewal for a single domain.
10. **`certmate_deploy_certificate`** — Manually executes all configured deployment hooks for a domain.
11. **`certmate_download_certificate`** — Returns a domain's certificate material as JSON (fullchain, key, chain) so an agent can deploy it elsewhere.

**Providers**
12. **`certmate_list_dns_providers`** — DNS providers supported and configured on this instance.
13. **`certmate_list_dns_accounts`** — Configured DNS provider accounts (credentials masked); use a returned account id as `account_id` when creating a certificate. **Requires `admin`.**

**Editing and removing**
14. **`certmate_update_certificate`** — Changes an existing certificate's coverage in place by reissuing it: replace the SAN set and/or the DNS-01 alias. The primary domain is the certificate's identity and cannot be changed here. Returns a `job_id`.
15. **`certmate_delete_certificate`** — **Destructive and not reversible.** Removes the certificate files from disk and the domain from settings. **Requires `admin`.**
16. **`certmate_get_certificate_file`** — Returns one certificate file as raw, pasteable PEM rather than JSON-wrapped. `cert.pem`, `chain.pem` and `fullchain.pem` are readable by a `viewer`; `privkey.pem`, `combined.pem` and `cert.pfx` carry key material and need `operator`.

## Roles

Give the agent the narrowest token that does its job, and note that a few tools
need more than the rest:

| Tool | Minimum role |
|---|---|
| everything under Inventory & status except diagnostics (`certmate_get_settings` returns secrets masked), `certmate_list_dns_providers`, `certmate_get_certificate_file` for `cert.pem` / `chain.pem` / `fullchain.pem` | `viewer` |
| `certmate_create_certificate`, `certmate_renew_certificate`, `certmate_get_job`, `certmate_set_auto_renew`, `certmate_update_certificate`, `certmate_download_certificate`, `certmate_get_certificate_file` for `privkey.pem` / `combined.pem` / `cert.pfx` | `operator` |
| `certmate_diagnostics` | `admin` |
| **`certmate_deploy_certificate`** | **`admin`** |
| **`certmate_list_dns_accounts`** | **`admin`** |
| **`certmate_delete_certificate`** | **`admin`** |

Deploy and account listing are the surprising ones: both read or act on stored
credentials, so both are `admin` on the server side even though an agent that
only renews would otherwise be happy with `operator`. An operator-scoped agent
asked to "pick an account and issue" will get a 403 on the account lookup — pass
the `account_id` in the prompt instead, or give it an admin token deliberately.

## Setup & Configuration

### Prerequisites
- Node.js (>= 20 — `mcp/package.json` declares `engines.node: ">=20.0.0"`)
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
- `CERTMATE_TOKEN` — A valid API Bearer token with appropriate role permissions (typically `operator` or `admin`). For an auditable agent, use a key flagged as an agent key (see [Audit attribution](#audit-attribution)).

Optional:
- `CERTMATE_AGENT_SESSION` — Overrides the per-process session id the server sends on every call (`X-CertMate-Agent-Session`), so a run can be correlated with an external orchestrator's id. A fresh UUID is generated per process if unset.
- `CERTMATE_AGENT_ID` — A label for this agent deployment (`X-CertMate-Agent-Id`, default `certmate-mcp-server`).

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
4. Each renewal returns a `job_id`; call `certmate_get_job` until it reports `succeeded` / `failed`.
5. On failure, surface it. A failed renew or reissue job also emits `certificate_failed`, so CertMate's own notification channels (email, Slack, Discord, Telegram, ntfy, Gotify) push it regardless. Two exceptions: a job that failed because another operation already held the domain (`error_code: DOMAIN_OPERATION_IN_PROGRESS`) does not emit it, and a failed async create does not either, so for those the agent's own report is the signal.

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
token scoped to exactly what it should do — `operator` for renew, `admin`
only if it must run deploy hooks, list DNS accounts, delete certificates, or read diagnostics.

## Security

1. **Token Protection** — The MCP server requires a valid `CERTMATE_TOKEN`. It sends this token in the `Authorization` header of every request to the CertMate API. The default `CERTMATE_URL` is plain `http://localhost:8000`; when CertMate runs on another host, use an `https://` URL, or the token crosses the network in clear text.
2. **Least privilege** — Scope the token to what the agent needs. A scheduled renew-keeper needs `operator`; reserve `admin` tokens for agents that must run deploy hooks, list DNS accounts, delete certificates, or pull diagnostics. Revoke the token to instantly cut the agent off.
3. **Log Sanitization Compatibility** — Tools like `certmate_diagnostics` retrieve data after the Log Sanitizer has stripped sensitive credentials, protecting keys and tokens from leaking into LLM contexts.

## Audit attribution

So the audit trail can tell an agent's actions apart from a human operator's,
give the MCP server a **dedicated, agent-flagged API key** rather than the legacy
global bearer token:

1. In CertMate, go to **Settings → API Keys**, create a key, and tick **AI agent
   key** (or send `"is_agent": true` to `POST /api/keys`). Give it the least role it needs,
   and for a `viewer` or `operator` key limit it with `allowed_domains`. An
   `admin` key cannot be domain-scoped: the server refuses it with a 400.
2. Set that key as `CERTMATE_TOKEN` for the MCP server.

Every certificate action the agent then takes is recorded with
`actor.kind="agent"`, the key's stable id, and the per-process
`X-CertMate-Agent-Session` the server sends — so you can later show exactly which
certificate changes an AI agent made, under which identity, and grouped by run.
The legacy global bearer token collapses every caller to `api_user` with no key
id and is recorded as `api_token`, not `agent`. The agent-session header is an
informational claim and never by itself promotes a caller to `agent`.

The resulting records are part of the tamper-evident audit chain; see
[Audit Logging](./api.md#audit-logging) and [compliance.md](./compliance.md).
