// The update tool reissues under the CA account it is given (#1546). The
// reissue API takes `ca_account_id` since API contract 2.76: an id is that
// account, "" is the CA's default account, and an omitted field keeps the
// account the certificate was issued under. The tool had no parameter for it,
// so a reissue from MCP always kept the recorded account.
//
// A server before 2.76 ignores the field and keeps the recorded account, which
// is what the parameter is there to change. So the tool asks /health for the
// contract first when it is given an account, and refuses, sending nothing,
// when the server would ignore it. Without one it asks nothing.
//
// No running CertMate required: the tool is driven over stdio against a local
// mock whose /health reports the contract each scenario sets.
//
// Run with: npm test   (from the mcp/ directory)
const http = require("http");
const path = require("path");
const { spawn } = require("child_process");

const INDEX = path.join(__dirname, "index.js");
const REISSUE = "/api/certificates/example.com/reissue";
const requests = [];
let contract = "2.76";
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
    if (req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(contract === null ? { status: "healthy" } : { status: "healthy", api_contract_version: contract }));
    } else {
      res.writeHead(202, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ job_id: "j1", status: "queued", domain: "example.com" }));
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
  const rpc = (method, params) => new Promise((resolve) => {
    const id = next++;
    waiting[id] = resolve;
    send({ jsonrpc: "2.0", id, method, params });
  });
  const update = (args) => rpc("tools/call", { name: "certmate_update_certificate", arguments: args });
  const reissues = () => requests.filter((r) => r.method === "POST" && r.url === REISSUE);
  const isError = (answer) => Boolean(answer.result && answer.result.isError);
  const text = (answer) => (answer.result && answer.result.content && answer.result.content[0] && answer.result.content[0].text) || "";
  const timeout = setTimeout(() => fail("timed out waiting for tool responses"), 8000);

  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "ca-account-test", version: "0" } } });
  setTimeout(async () => {
    send({ jsonrpc: "2.0", method: "notifications/initialized" });

    // The schema states the three meanings, as docs/api.md does.
    const listed = await rpc("tools/list", {});
    const tool = (listed.result.tools || []).find((t) => t.name === "certmate_update_certificate");
    const param = tool && tool.inputSchema.properties.ca_account_id;
    if (!param || param.type !== "string") fail(`the update tool has no string ca_account_id: ${JSON.stringify(tool)}`);
    for (const meaning of [/omit/i, /""/, /default account/i, /2\.76/]) {
      if (!meaning.test(param.description)) fail(`ca_account_id's description does not say ${meaning}: ${param.description}`);
    }

    // Absent: the field is left out, and nothing is asked first, so a plain
    // reissue still runs against a server that predates the field.
    contract = "2.75";
    requests.length = 0;
    let answer = await update({ domain: "example.com" });
    if (isError(answer)) fail(`a reissue without an account was refused: ${text(answer)}`);
    if (requests.map((r) => r.url).join(",") !== REISSUE) {
      fail(`a reissue without an account asked more than the reissue: ${JSON.stringify(requests)}`);
    }
    if (JSON.stringify(reissues()[0].body) !== JSON.stringify({ async: true })) {
      fail(`a reissue without an account sent more than async: ${JSON.stringify(reissues()[0].body)}`);
    }

    // An id, and "" for the CA's default account: each is sent as given.
    contract = "2.76";
    for (const account of ["acct-2", ""]) {
      requests.length = 0;
      answer = await update({ domain: "example.com", ca_account_id: account });
      if (isError(answer)) fail(`a reissue under ${JSON.stringify(account)} was refused: ${text(answer)}`);
      const sent = reissues();
      if (sent.length !== 1 || JSON.stringify(sent[0].body) !== JSON.stringify({ async: true, ca_account_id: account })) {
        fail(`a reissue under ${JSON.stringify(account)} sent ${JSON.stringify(sent.map((r) => r.body))}`);
      }
    }

    // Servers that would ignore it: refused with the contract it needs, and
    // nothing is sent.
    for (const older of ["2.75", "2.9", null]) {
      for (const account of ["acct-2", ""]) {
        contract = older;
        requests.length = 0;
        answer = await update({ domain: "example.com", ca_account_id: account });
        if (reissues().length) fail(`a reissue was sent to a server on ${older}: ${JSON.stringify(requests)}`);
        if (!isError(answer) || !/2\.76/.test(text(answer))) {
          fail(`a server on ${older} was not refused with the contract the account needs: ${JSON.stringify(answer.result)}`);
        }
      }
    }

    // Not a string: refused before anything is sent, rather than passed on
    // for the server to read some other way.
    contract = "2.76";
    for (const wrong of [5, true, ["acct-2"]]) {
      requests.length = 0;
      answer = await update({ domain: "example.com", ca_account_id: wrong });
      if (requests.length) fail(`a ca_account_id of ${JSON.stringify(wrong)} reached the server: ${JSON.stringify(requests)}`);
      if (!isError(answer) || !/ca_account_id/.test(text(answer))) {
        fail(`a ca_account_id of ${JSON.stringify(wrong)} was not refused: ${JSON.stringify(answer.result)}`);
      }
    }

    clearTimeout(timeout);
    console.log("OK: update leaves ca_account_id out when absent, sends an id and \"\" as given to a 2.76 server, refuses one that would ignore it, and refuses a non-string");
    console.log("PASS");
    cleanup();
    process.exit(0);
  }, 400);
});
