// Smoke test for the CertMate MCP server — no running CertMate required.
//
// 1. Static consistency: every tool declared in ListTools has a switch case
//    and vice-versa.
// 2. Live stdio handshake: spawn the server, complete the MCP initialize
//    handshake, and assert tools/list returns every declared tool.
//
// Run with: npm test   (from the mcp/ directory)
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const INDEX = path.join(__dirname, "index.js");
const src = fs.readFileSync(INDEX, "utf8");

const declared = [...src.matchAll(/name:\s*"(certmate_[a-z_]+)"/g)].map((m) => m[1]);
const cases = [...src.matchAll(/case\s*"(certmate_[a-z_]+)"/g)].map((m) => m[1]);

function fail(msg) {
  console.error("FAIL:", msg);
  process.exit(1);
}

// --- 1. static consistency ---
const declaredSet = new Set(declared);
const caseSet = new Set(cases);
const missingCase = declared.filter((n) => !caseSet.has(n));
const missingDecl = cases.filter((c) => !declaredSet.has(c));
if (missingCase.length) fail(`tools declared without a switch case: ${missingCase}`);
if (missingDecl.length) fail(`switch cases without a tool declaration: ${missingDecl}`);
console.log(`OK: ${declared.length} tools, declarations and switch cases consistent`);

// --- 2. live stdio handshake ---
const child = spawn("node", [INDEX], {
  env: { ...process.env, CERTMATE_TOKEN: "dummy" },
  stdio: ["pipe", "pipe", "pipe"],
});

let buf = "";
const timeout = setTimeout(() => {
  child.kill();
  fail("timed out waiting for tools/list response");
}, 8000);

child.stdout.on("data", (d) => {
  buf += d.toString();
  let idx;
  while ((idx = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, idx);
    buf = buf.slice(idx + 1);
    if (!line.trim()) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch (e) {
      continue;
    }
    if (msg.id === 2 && msg.result && msg.result.tools) {
      clearTimeout(timeout);
      const names = msg.result.tools.map((t) => t.name);
      child.kill();
      if (names.length !== declared.length) {
        fail(`tools/list returned ${names.length}, expected ${declared.length}`);
      }
      for (const n of declared) {
        if (!names.includes(n)) fail(`tools/list missing declared tool ${n}`);
      }
      console.log(`OK: stdio handshake -> tools/list returned all ${names.length} tools`);
      console.log("PASS");
      process.exit(0);
    }
  }
});

child.stderr.on("data", () => {}); // swallow the "running on stdio" banner

const init = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "smoke", version: "0" } },
};
child.stdin.write(JSON.stringify(init) + "\n");
setTimeout(() => {
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) + "\n");
}, 400);
