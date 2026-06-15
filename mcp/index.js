const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require("@modelcontextprotocol/sdk/types.js");
const fetch = require("node-fetch");
const { randomUUID } = require("crypto");

// Stable id for this agent process, sent on every CertMate call so the audit
// trail can group an agent session's actions. It is an INFORMATIONAL claim:
// CertMate derives the trustworthy actor identity from the authenticated API
// key, never from this header. Override via CERTMATE_AGENT_SESSION (e.g. to
// correlate with an external orchestrator's run id).
const AGENT_SESSION = process.env.CERTMATE_AGENT_SESSION || randomUUID();
const AGENT_ID = process.env.CERTMATE_AGENT_ID || "certmate-mcp-server";

const server = new Server({
  name: "certmate-mcp-server",
  version: "1.1.0"
}, {
  capabilities: {
    tools: {}
  }
});

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "certmate_list_certificates",
        description: "List all configured certificates on the CertMate instance, including their expiry, status, and domains.",
        inputSchema: { type: "object", properties: {} }
      },
      {
        name: "certmate_create_certificate",
        description: "Create a new TLS certificate for a specified domain.",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "The primary domain name for the certificate (e.g. example.com)" },
            dns_provider: { type: "string", description: "The DNS provider key (optional)" },
            account_id: { type: "string", description: "The account ID for the DNS provider (optional)" },
            ca_provider: { type: "string", description: "The Certificate Authority (CA) to use (optional)" }
          },
          required: ["domain"]
        }
      },
      {
        name: "certmate_renew_certificate",
        description: "Force renewal of an existing certificate for a domain.",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "The domain name of the certificate to renew" }
          },
          required: ["domain"]
        }
      },
      {
        name: "certmate_deploy_certificate",
        description: "Manually execute all configured deployment hooks for a domain.",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "The domain name of the certificate to deploy" }
          },
          required: ["domain"]
        }
      },
      {
        name: "certmate_get_settings",
        description: "Retrieve the global settings and configurations of the CertMate instance.",
        inputSchema: { type: "object", properties: {} }
      },
      {
        name: "certmate_diagnostics",
        description: "Retrieve a comprehensive and sanitized diagnostic snapshot of the CertMate system.",
        inputSchema: { type: "object", properties: {} }
      },
      {
        name: "certmate_get_certificate",
        description: "Get full detail for one certificate by domain: status, days until expiry, SANs, DNS/CA provider, auto-renew flag. Use this to decide whether a cert needs renewing (e.g. renew when days_left < 14).",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "The domain name (e.g. example.com)" }
          },
          required: ["domain"]
        }
      },
      {
        name: "certmate_get_job",
        description: "Poll the status of an asynchronous certificate job. certmate_create_certificate and certmate_renew_certificate may return a job_id (HTTP 202); call this with that job_id until status is completed or failed.",
        inputSchema: {
          type: "object",
          properties: {
            job_id: { type: "string", description: "The job_id returned by an async create/renew" }
          },
          required: ["job_id"]
        }
      },
      {
        name: "certmate_download_certificate",
        description: "Download a certificate's material as JSON (fullchain, private key, chain) for a domain, so an agent can deploy it elsewhere.",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "The domain name" }
          },
          required: ["domain"]
        }
      },
      {
        name: "certmate_set_auto_renew",
        description: "Enable or disable automatic renewal for a single domain.",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "The domain name" },
            enabled: { type: "boolean", description: "true to enable auto-renew, false to disable" }
          },
          required: ["domain", "enabled"]
        }
      },
      {
        name: "certmate_list_dns_providers",
        description: "List the DNS providers supported and configured on this instance, so a create call can pass a valid dns_provider.",
        inputSchema: { type: "object", properties: {} }
      },
      {
        name: "certmate_list_dns_accounts",
        description: "List configured DNS provider accounts (credentials are masked). Pass a provider to filter; omit to list all. Use a returned account id as account_id when creating a certificate.",
        inputSchema: {
          type: "object",
          properties: {
            provider: { type: "string", description: "Optional DNS provider key to filter by (e.g. cloudflare)" }
          }
        }
      },
      {
        name: "certmate_get_activity",
        description: "Read the recent activity/audit log to diagnose what changed or what failed.",
        inputSchema: {
          type: "object",
          properties: {
            limit: { type: "integer", description: "Max entries to return (1-500, default 100)" }
          }
        }
      }
    ]
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const baseUrl = process.env.CERTMATE_URL || "http://localhost:8000";
  const token = process.env.CERTMATE_TOKEN;

  if (!token) {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: "Error: CERTMATE_TOKEN environment variable is not defined."
        }
      ]
    };
  }

  const headers = {
    "Authorization": `Bearer ${token}`,
    "Content-Type": "application/json",
    "X-CertMate-Agent-Session": AGENT_SESSION,
    "X-CertMate-Agent-Id": AGENT_ID
  };

  async function makeRequest(method, path, body = null) {
    const url = `${baseUrl.replace(/\/$/, '')}${path}`;
    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : null
      });

      if (!response.ok) {
        let errText = `HTTP error ${response.status}`;
        try {
          const errBody = await response.json();
          errText += `: ${errBody.error || errBody.message || JSON.stringify(errBody)}`;
        } catch (e) {
          try {
            errText += `: ${await response.text()}`;
          } catch (e2) {}
        }
        throw new Error(errText);
      }

      if (response.status === 204) {
        return { success: true };
      }
      return await response.json();
    } catch (error) {
      throw new Error(`Request to ${url} failed: ${error.message}`);
    }
  }

  try {
    let result;
    switch (name) {
      case "certmate_list_certificates":
        result = await makeRequest("GET", "/api/certificates");
        break;
      case "certmate_create_certificate":
        result = await makeRequest("POST", "/api/certificates/create", {
          domain: args.domain,
          dns_provider: args.dns_provider,
          account_id: args.account_id,
          ca_provider: args.ca_provider
        });
        break;
      case "certmate_renew_certificate":
        result = await makeRequest("POST", `/api/certificates/${encodeURIComponent(args.domain)}/renew`);
        break;
      case "certmate_deploy_certificate":
        result = await makeRequest("POST", `/api/certificates/${encodeURIComponent(args.domain)}/deploy`);
        break;
      case "certmate_get_settings":
        result = await makeRequest("GET", "/api/settings");
        break;
      case "certmate_diagnostics":
        result = await makeRequest("GET", "/api/diagnostics/snapshot");
        break;
      case "certmate_get_certificate":
        result = await makeRequest("GET", `/api/certificates/${encodeURIComponent(args.domain)}`);
        break;
      case "certmate_get_job":
        result = await makeRequest("GET", `/api/certificates/jobs/${encodeURIComponent(args.job_id)}`);
        break;
      case "certmate_download_certificate":
        result = await makeRequest("GET", `/api/certificates/${encodeURIComponent(args.domain)}/download?format=json`);
        break;
      case "certmate_set_auto_renew":
        result = await makeRequest("PUT", `/api/certificates/${encodeURIComponent(args.domain)}/auto-renew`, {
          enabled: args.enabled
        });
        break;
      case "certmate_list_dns_providers":
        result = await makeRequest("GET", "/api/settings/dns-providers");
        break;
      case "certmate_list_dns_accounts":
        result = await makeRequest("GET", args.provider
          ? `/api/dns/${encodeURIComponent(args.provider)}/accounts`
          : "/api/dns/accounts");
        break;
      case "certmate_get_activity":
        result = await makeRequest("GET", `/api/activity?limit=${encodeURIComponent(args.limit || 100)}`);
        break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2)
        }
      ]
    };
  } catch (error) {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: `Error executing ${name}: ${error.message}`
        }
      ]
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("CertMate MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error in main:", error);
  process.exit(1);
});
