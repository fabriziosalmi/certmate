# CertMate Model Context Protocol (MCP) Server

CertMate includes a built-in Model Context Protocol (MCP) server written in Node.js. This allows agentic AI assistants (such as Claude or Gemini) to securely inspect certificate statuses, trigger renewals, request diagnostics, and interact with the CertMate API directly.

## Capabilities & Tools

The CertMate MCP server exposes the following tools to AI assistants:

1. **`certmate_list_certificates`** — Lists all certificates managed by the active CertMate instance.
2. **`certmate_create_certificate`** — Requests a new TLS certificate for a specified domain (supports optional parameters for DNS provider, account, and CA).
3. **`certmate_renew_certificate`** — Forces renewal of an existing certificate for a domain.
4. **`certmate_deploy_certificate`** — Manually executes all configured deployment hooks for a domain.
5. **`certmate_get_settings`** — Retrieves global settings and configurations.
6. **`certmate_diagnostics`** — Retrieves a comprehensive and sanitized diagnostic snapshot of the CertMate system.

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

## Security

1. **Token Protection** — The MCP server requires a valid `CERTMATE_TOKEN`. It passes this token securely in the `Authorization` header for all requests to the CertMate API.
2. **Log Sanitization Compatibility** — Tools like `certmate_diagnostics` retrieve data after the Log Sanitizer has stripped sensitive credentials, protecting keys and tokens from leaking into LLM contexts.
