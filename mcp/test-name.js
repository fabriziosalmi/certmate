// The create tool names a certificate apart from its domain (#1149). The server
// takes `name` since API contract 2.61 and, before it, ignores the field and
// issues the certificate under its domain. So the tool asks /health for the
// contract first, and refuses, sending nothing, when the server would ignore
// the name. Without a name it asks nothing.
//
// No running CertMate required: the tool is driven over stdio against a local
// mock whose /health reports the contract each scenario sets.
//
// Run with: npm test   (from the mcp/ directory)
const http = require("http");
const path = require("path");
const { spawn } = require("child_process");

const INDEX = path.join(__dirname, "index.js");
const requests = [];
let contract = "2.61";
let server;
let child;

function cleanup() {
  try { if (child) child.kill(); } catch (e) {}
  try { if (server) server.close(); } catch (e) {}
}
function fail(msg) {
  console.error("FAIL:", msg);
  cleanup();
  process.exit(1);
}

server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const raw = Buffer.concat(chunks).toString();
    let body = null;
    try { body = raw ? JSON.parse(raw) : null; } catch (e) { body = raw; }
    requests.push({ method: req.method, url: req.url, body });
    res.writeHead(req.url === "/api/certificates/create" ? 202 : 200, { "Content-Type": "application/json" });
    if (req.url === "/health") {
      res.end(JSON.stringify(contract === null ? { status: "healthy" } : { status: "healthy", api_contract_version: contract }));
    } else {
      res.end(JSON.stringify({ job_id: "j1", status: "queued", domain: (body && (body.name || body.domain)) || "" }));
    }
  });
});

server.listen(0, "127.0.0.1", () => {
  const port = server.address().port;
  child = spawn("node", [INDEX], {
    env: { ...process.env, CERTMATE_TOKEN: "test-token", CERTMATE_URL: `http://127.0.0.1:${port}` },
    stdio: ["pipe", "pipe", "pipe"],
  });

  const waiting = {};
  let buf = "";
  child.stdout.on("data", (d) => {
    buf += d.toString();
    let idx;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      let msg;
      try { msg = JSON.parse(line); } catch (e) { continue; }
      if (msg.id && waiting[msg.id]) waiting[msg.id](msg);
    }
  });
  child.stderr.on("data", () => {});

  const send = (obj) => child.stdin.write(JSON.stringify(obj) + "\n");
  let next = 10;
  const create = (args) => new Promise((resolve) => {
    const id = next++;
    waiting[id] = resolve;
    send({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "certmate_create_certificate", arguments: args } });
  });
  const timeout = setTimeout(() => fail("timed out waiting for tool responses"), 8000);

  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "name-test", version: "0" } } });
  setTimeout(async () => {
    send({ jsonrpc: "2.0", method: "notifications/initialized" });

    // A server that takes the name: it is sent with the domain.
    contract = "2.61";
    requests.length = 0;
    let answer = await create({ domain: "example.com", name: "internal.example.com" });
    const sent = requests.find((r) => r.method === "POST" && r.url === "/api/certificates/create");
    if (!sent) fail(`no create was sent: ${JSON.stringify(requests)}`);
    if (sent.body.domain !== "example.com" || sent.body.name !== "internal.example.com") {
      fail(`the create did not carry the name with the domain: ${JSON.stringify(sent.body)}`);
    }
    if (answer.result && answer.result.isError) fail(`a 2.61 server was refused: ${JSON.stringify(answer.result)}`);

    // Servers that would ignore it: refused, and nothing is sent.
    for (const older of ["2.60", "2.9", null]) {
      contract = older;
      requests.length = 0;
      answer = await create({ domain: "example.com", name: "internal.example.com" });
      if (requests.some((r) => r.method === "POST")) {
        fail(`a create was sent to a server on ${older}: ${JSON.stringify(requests)}`);
      }
      const text = answer.result && answer.result.content && answer.result.content[0] && answer.result.content[0].text;
      if (!(answer.result && answer.result.isError) || !/2\.61/.test(text || "")) {
        fail(`a server on ${older} was not refused with the contract the name needs: ${JSON.stringify(answer.result)}`);
      }
    }

    // Without a name, nothing is asked first, and no name is sent.
    contract = "2.60";
    requests.length = 0;
    await create({ domain: "example.com" });
    if (requests.map((r) => r.url).join(",") !== "/api/certificates/create") {
      fail(`a create without a name asked more than the create: ${JSON.stringify(requests)}`);
    }
    if (Object.prototype.hasOwnProperty.call(requests[0].body, "name")) {
      fail(`a create without a name sent one: ${JSON.stringify(requests[0].body)}`);
    }

    clearTimeout(timeout);
    console.log("OK: create sends the name to a 2.61 server, refuses one that would ignore it, and asks nothing without it");
    console.log("PASS");
    cleanup();
    process.exit(0);
  }, 400);
});
