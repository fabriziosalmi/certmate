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
- **Independent verification.** A standalone, standard-library-only verifier
  (`python -m modules.core.audit_verify`) recomputes the chain and returns
  PASS/FAIL without needing to run or trust CertMate; `GET /api/audit/verify`
  exposes the same check over the API.

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

- **The chain does not bind the operator.** It detects tampering by anyone
  **without** the writer's running state, but the operator holds the file and
  could recompute and re-sign the whole chain. Constraining the operator requires
  external anchoring of signed checkpoints off the box — **not implemented in
  this version**. Treat the current guarantee as "authenticity and ordering of
  the recorded entries", verifiable by a third party who holds an exported copy.
- **Authenticity, not completeness.** Audit writes are best-effort and never
  block a certificate operation; the chain proves the recorded entries are
  authentic and ordered, and a missing interior `seq` proves a deletion, but a
  write that failed before it was recorded leaves no entry to verify.
- **Tail truncation is not detected on its own.** Removing entries from the
  **end** of the chain leaves a shorter-but-internally-consistent chain that
  still verifies as intact — the verifier has no external reference for the
  expected head. Detecting tail truncation requires an external head anchor
  (the signed-checkpoint anchoring of Phase 3, not in this version). Until then,
  treat "intact" as "the entries present are authentic and in order", and keep
  an out-of-band record of the latest `head_hash` / `last_seq` if you need to
  detect end-removal.
- **The agent-session header is a claim.** It is recorded for correlation but is
  client-supplied; the trustworthy identity is the authenticated API key.
- **History boundary.** The chain starts when the feature is first enabled;
  earlier `.log` history is not part of the verifiable chain.

If your obligations require binding the operator themselves (off-box anchoring,
signed exports an external auditor pins to a published key), that is planned but
not yet available — track it before relying on it.
