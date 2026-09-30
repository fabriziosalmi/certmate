# certmate-mcp-server

A [Model Context Protocol](https://modelcontextprotocol.io) server for [CertMate](https://github.com/fabriziosalmi/certmate). It lets an AI agent list, issue, renew, reissue, deploy and inspect TLS certificates through CertMate's REST API, with every action attributed to the agent in CertMate's audit trail.

It speaks MCP over stdio, so it works with any MCP client: Claude Desktop, Claude Code, Cursor, Gemini and others.

## Requirements

- Node.js 20 or later.
- A running CertMate instance, and an API key for it. Use the least role that does the job: a `viewer` key can only read. For an auditable agent, create a key flagged as an agent key.

## Configure

The server reads two environment variables:

| Variable | Meaning |
| --- | --- |
| `CERTMATE_URL` | The CertMate instance, e.g. `http://localhost:8000` (the default) |
| `CERTMATE_TOKEN` | An API bearer token for that instance |

### Claude Desktop, Cursor, and other JSON-configured clients

```json
{
  "mcpServers": {
    "certmate": {
      "command": "npx",
      "args": ["-y", "certmate-mcp-server"],
      "env": {
        "CERTMATE_URL": "http://localhost:8000",
        "CERTMATE_TOKEN": "your_api_token"
      }
    }
  }
}
```

For Claude Desktop the file is `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS and `%APPDATA%\Claude\claude_desktop_config.json` on Windows. For Cursor it is `~/.cursor/mcp.json`.

### Claude Code

```bash
claude mcp add certmate --scope user \
  -e CERTMATE_URL=http://localhost:8000 \
  -e CERTMATE_TOKEN=your_api_token \
  -- npx -y certmate-mcp-server
```

## Tools, roles and audit attribution

The list of tools, which role each one needs, how agent actions appear in CertMate's audit trail, and examples of scheduled agent jobs are in the full guide: [docs/mcp.md](https://github.com/fabriziosalmi/certmate/blob/main/docs/mcp.md).

## License

MIT
