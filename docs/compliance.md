# Compliance and the audit trail

This page maps CertMate's audit trail to the regimes operators most often ask
about — the EU AI Act, NIS2, and ISO/IEC 42001 — when they let an AI/MCP agent
operate certificates on a schedule.

> **Read this first.** CertMate is a single-instance, self-hosted MIT tool. It is
> **not** an AI system, **not** a high-risk AI system, and **not** a regulated
> entity, and it does not "comply with" or "certify" anything. Compliance
> obligations fall on the **operator** running it. What CertMate provides is
> **evidence artifacts** an operator can use toward *their own* obligations.
> Every claim below is "enables the operator to evidence X", with the limits
> stated explicitly.

## What the audit trail provides today

- **Attribution.** Every certificate-lifecycle action — create, renew, reissue,
  deploy, auto-renew toggle, and unattended scheduled renewals — is recorded
  with a structured `actor` (human vs API token vs AI agent, down to the API key
  id) and `trigger` (manual, API, agent, or the scheduler job). An AI agent's
  actions are distinguishable from a human's, provided the agent uses an
  `is_agent`-flagged key. See [API: Audit Logging](./api.md#audit-logging) and
  the [MCP guide](./mcp.md#audit-attribution).
- **Tamper-evidence.** Entries are written into an append-only SHA-256 hash
  chain (`data/audit/certificate_audit.chain.jsonl`). Any modification,
  deletion, or reorder by someone who cannot recompute the chain is detectable
  and localizable.
- **Independent verification.** A standalone verifier
  (`python -m modules.core.audit_verify`) recomputes the chain and returns
  PASS/FAIL without needing to run or trust CertMate; `GET /api/audit/verify`
  exposes the same check over the API and, when signing is enabled, also
  cross-checks the chain against the latest signed checkpoint — so a tail
  truncation or rewrite at or below that checkpoint fails verification (see
  "tail truncation" under Honest limits).
- **Signed, third-party-verifiable export.** The instance signs the chain head
  (periodic checkpoints) and `GET /api/audit/export` produces an Ed25519-signed
  bundle. An auditor verifies it off the box, pinning the instance's public key
  (`GET /api/audit/public-key`) out of band — proving both that the record was
  not edited and which instance produced it.

## Regime mapping

### NIS2 (Directive (EU) 2022/2555) — the strongest fit

- **What it helps with.** Certificate operations change the trust posture of
  services, so they are security-relevant events. CertMate produces a
  tamper-evident, attributed, time-stamped record of every such operation, plus
  an independently verifiable check — usable as part of the operator's logging
  (Art. 21) and incident-evidence (Art. 23) practices.
- **Limit.** NIS2 binds essential/important **entities**, not software tools.
  CertMate supplies logs and a verifier the operator can use; it does not assess,
  monitor, or report incidents, and being an in-scope entity (and meeting NIS2 in
  full) is the operator's responsibility.

### EU AI Act — Article 50 transparency (spirit only; the weakest fit)

- **What it helps with.** When an AI agent autonomously operates PKI, the record
  carries an explicit `actor.kind="agent"` marker plus the agent session, so the
  operator can demonstrate after the fact which changes were made by an AI agent
  versus a human, under which identity, and what triggered them — supporting the
  transparency and human-oversight spirit of the Act.
- **Limit.** Art. 50 duties fall on **providers/deployers of AI systems** and
  concern disclosure to natural persons interacting with AI. An agent renewing
  TLS certificates is not a textbook Art. 50 case, and CertMate is a tool, not an
  AI system. We map to the transparency spirit only; CertMate does **not** satisfy
  Art. 50 on anyone's behalf.

### ISO/IEC 42001 (AI management system) — operational records

- **What it helps with.** The attributed, tamper-evident records are objective
  evidence that an AI agent took specific certificate actions — usable for the
  operational-records and traceability controls of the operator's own AIMS.
- **Limit.** ISO 42001 certifies an organisation's management system, not a tool.
  CertMate is not certified to ISO 42001 and cannot certify the operator; it
  produces records the operator can present as evidence for their own controls.

## Honest limits (do not over-read these)

- **The signing key does not bind the operator.** A signed export bundle (and
  the periodic signed checkpoints) let a third party verify, off the box, which
  instance produced the record and that it was not edited — for anyone who does
  **not** hold the signing key. But the operator holds the key and could re-sign
  a rewritten chain. Fully constraining the operator requires shipping the signed
  checkpoints to an external append-only sink (**opt-in external anchoring — a
  planned follow-up, not yet shipped**). Treat the current guarantee as
  "authenticity, ordering, and instance attribution of the recorded entries",
  independently verifiable by a third party who holds an exported, signed copy.
- **Authenticity, not completeness.** Audit writes are best-effort and never
  block a certificate operation; the chain proves the recorded entries are
  authentic and ordered, and a missing interior `seq` proves a deletion, but a
  write that failed before it was recorded leaves no entry to verify.
- **Tail truncation is caught down to the last signed checkpoint.** Removing
  entries from the **end** of the chain leaves a shorter-but-internally-
  consistent chain. `GET /api/audit/verify` now cross-checks the chain against
  the newest signed checkpoint that verifies under the instance key, so any
  truncation, rewind, or rewrite **at or below** that checkpoint fails
  verification — the previously write-only checkpoints are now read back. Two
  gaps remain: (a) entries written **after** the last checkpoint can still be
  dropped undetected until the next checkpoint seals them, and (b) an operator
  who holds the signing key can re-sign a fresh checkpoint over a rewritten
  chain. Keep successive signed exports, or wait for opt-in external anchoring,
  if you need to close those.
- **The agent-session header is a claim.** It is recorded for correlation but is
  client-supplied; the trustworthy identity is the authenticated API key.
- **History boundary.** The chain starts when the feature is first enabled;
  earlier `.log` history is not part of the verifiable chain.

Signed exports that an external auditor pins to a published key are available
today. If your obligations require binding the operator *themselves* — so that
even the key-holder cannot rewrite history undetected — that needs opt-in
external anchoring of the signed checkpoints to an append-only sink off the box,
which is planned but not yet shipped. Track it before relying on it.
