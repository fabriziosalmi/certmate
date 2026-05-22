const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require("@modelcontextprotocol/sdk/types.js");
const fetch = require("node-fetch");

const server = new Server({
  name: "certmate-mcp-server",
  version: "1.0.0"
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
    "Content-Type": "application/json"
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
