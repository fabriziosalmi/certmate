// Behavioral test for the lifecycle tools added in #358 — delete / update /
// get_certificate_file. No running CertMate required: it spawns the MCP server
// pointed at a local mock that records every request, calls each tool over
// stdio, and asserts the right HTTP method/path/body went out (and that
// get_certificate_file returns RAW PEM, not JSON-wrapped).
//
// Run with: npm test   (from the mcp/ directory)
const http = require("http");
const path = require("path");
const { spawn } = require("child_process");

const INDEX = path.join(__dirname, "index.js");
const requests = [];
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

// Mock CertMate: record each request; return raw PEM for ?file= downloads and
// a small JSON body for everything else.
server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const raw = Buffer.concat(chunks).toString();
    let body = null;
    try { body = raw ? JSON.parse(raw) : null; } catch (e) { body = raw; }
    requests.push({ method: req.method, url: req.url, body, auth: req.headers["authorization"] });
    if (req.url.indexOf("/download?file=") !== -1) {
      res.writeHead(200, { "Content-Type": "application/x-pem-file" });
      res.end("-----BEGIN CERTIFICATE-----\nMOCKPEM\n-----END CERTIFICATE-----\n");
    } else {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true }));
    }
  });
});

server.listen(0, "127.0.0.1", () => {
  const port = server.address().port;
  child = spawn("node", [INDEX], {
    env: { ...process.env, CERTMATE_TOKEN: "test-token", CERTMATE_URL: `http://127.0.0.1:${port}` },
    stdio: ["pipe", "pipe", "pipe"],
  });

  const responses = {};
  let buf = "";
  let started = false; // fire the first-round assertions exactly once
  const timeout = setTimeout(() => fail("timed out waiting for tool responses"), 8000);

  child.stdout.on("data", (d) => {
    buf += d.toString();
    let idx;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch (e) { continue; }
      if (msg.id) responses[msg.id] = msg;
      if (!started && responses[10] && responses[11] && responses[12]) {
        started = true;
        clearTimeout(timeout);
        finish();
        return;
      }
    }
  });
  child.stderr.on("data", () => {}); // swallow the startup banner

  const send = (obj) => child.stdin.write(JSON.stringify(obj) + "\n");
  const call = (id, name, args) =>
    send({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });

  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "tools-test", version: "0" } } });
  setTimeout(() => {
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    call(10, "certmate_delete_certificate", { domain: "old.example.com" });
    call(11, "certmate_update_certificate", { domain: "api.example.com", sans: ["www.api.example.com"], domain_alias: "alias.example.net" });
    call(12, "certmate_get_certificate_file", { domain: "api.example.com", file: "fullchain.pem" });
  }, 400);

  function finish() {
    if (process.env.MCP_TEST_DEBUG) {
      console.error("DEBUG requests:", JSON.stringify(requests));
      console.error("DEBUG resp10:", JSON.stringify(responses[10]));
      console.error("DEBUG resp12:", JSON.stringify(responses[12]));
    }
    const del = requests.find((r) => r.method === "DELETE" && r.url === "/api/certificates/old.example.com");
    if (!del) fail(`delete did not issue DELETE /api/certificates/old.example.com — saw ${JSON.stringify(requests.map((r) => r.method + " " + r.url))}`);
    if (del.auth !== "Bearer test-token") fail("delete request missing 'Authorization: Bearer test-token'");

    const upd = requests.find((r) => r.method === "POST" && r.url === "/api/certificates/api.example.com/reissue");
    if (!upd) fail("update did not POST /api/certificates/api.example.com/reissue");
    if (!upd.body || JSON.stringify(upd.body.san_domains) !== JSON.stringify(["www.api.example.com"]) || upd.body.domain_alias !== "alias.example.net") {
      fail(`update sent the wrong reissue body: ${JSON.stringify(upd.body)}`);
    }

    const getf = requests.find((r) => r.method === "GET" && r.url === "/api/certificates/api.example.com/download?file=fullchain.pem");
    if (!getf) fail("get_certificate_file did not GET /api/certificates/api.example.com/download?file=fullchain.pem");

    const r12 = responses[12];
    const text12 = r12 && r12.result && r12.result.content && r12.result.content[0] && r12.result.content[0].text;
    if (!text12 || text12.indexOf("BEGIN CERTIFICATE") === -1 || text12.trim().charAt(0) === "{") {
      fail(`get_certificate_file did not return raw PEM text: ${JSON.stringify(text12)}`);
    }

    // update omitting sans must NOT send san_domains (keep-current semantics).
    requests.length = 0;
    call(13, "certmate_update_certificate", { domain: "api.example.com", domain_alias: "" });
    setTimeout(() => {
      const upd2 = requests.find((r) => r.method === "POST" && r.url === "/api/certificates/api.example.com/reissue");
      if (!upd2) fail("second update did not POST reissue");
      if (Object.prototype.hasOwnProperty.call(upd2.body || {}, "san_domains")) {
        fail(`update without sans must omit san_domains; sent ${JSON.stringify(upd2.body)}`);
      }
      if (upd2.body.domain_alias !== "") fail("update should pass domain_alias='' to clear the alias");
      console.log("OK: delete -> DELETE; update -> POST reissue (body, and san_domains omitted when sans absent); get_file -> GET ?file= returning raw PEM");
      console.log("PASS");
      cleanup();
      process.exit(0);
    }, 300);
  }
});
