# Security model and threat assumptions

CSE is a research prototype intended to support security-by-design architecture. It is **not** a standalone authorization system or prompt-injection sanitizer.

## Trust boundaries

| Boundary | Owned by | Control |
|---|---|---|
| Actor-to-tenant and actor-to-scope | Authenticated enterprise gateway | Verify signed identity, derive principal and clearance |
| Document ingestion | Source connector / ingestion control plane | Authenticate document origin, record integrity digest in trusted manifest |
| Context admission | CSE policy module | Tenant, clearance, ACL, time, digest, input-size limits |
| Context ranking | Optional scorer | May only score already authorized input; not an authorization authority |
| Remote model egress | Gateway + CSE policy | Explicit opt-in, classification ceiling, scoped provider token |
| Action execution | Separate tool / policy enforcement point | Independently authorize every side effect; never authorize by relevance score |
| Prompt and output handling | Target LLM harness | Treat source text as untrusted data; enforce instruction hierarchy |
| Storage / cache | Gateway | Encryption, tenant partitioning, expiry and revocation; CSE does not persist |

## Threat scenarios and current response

- **Cross-tenant leakage**: item tenant must match principal tenant, regardless of label or model score. Rejected items never reach a remote scorer. Result diagnostics do not expose blocked item IDs.
- **Credential or privilege escalation**: clearance and restricted ACL are evaluated deterministically. These inputs are *not* independently authenticated inside CSE. An untrusted caller able to choose `principal` could bypass the boundary: therefore do not expose the CLI's input contract as an unguarded network endpoint.
- **Stale evidence**: past `expires_at` or future `not_before` is excluded. In-progress revocation requires a fresh compile and downstream cancellation; currently not automated.
- **Tampering**: mismatch or missing SHA-256 is excluded by default. A compromised producer can recompute the digest, so authentication requires a protected trusted ingestion manifest (not implemented).
- **Dependency loss**: if a needed dependency is absent or blocked, the parent cannot be selected. Mandatory requirements cause the whole compilation to block.
- **Conflicting records**: explicit `conflicts_with` pairs prevent co-selection; conflicting compulsory items block. No automated semantic contradiction detection.
- **Prompt injection**: the output is JSON with an `untrusted_evidence` key. This reduces accidental boundary confusion but is *not* sufficient protection against malicious source text. No code in CSE executes instructions from item content.
- **Exfiltration through model provider**: cloud inference is disabled by default and task classification must meet the configured egress ceiling. The request payload contains task and eligible item contents; enable only for data approved for third-party processing.
- **Model outage or malformed prediction**: a recoverable cloud scoring failure degrades to the local lexical scorer; a noncompliant or malformed local scorer raises an exception. Neither changes mandatory evidence or ACL enforcement.
- **Data retention**: no storage, telemetry, logs, caches, or server-side credentials by default. Gateway, model provider, and cloud platform retention policies are separate concerns.

## Production hardening checklist

- Derive principal and classification from verified IAM / token claims and trusted classification controls, not arbitrary request fields.
- Anchor digest and source version in a protected provenance ledger or signed manifest.
- Require a separate deterministic action authorization decision after compilation.
- Add per-tenant quotas, rate limits, reliable timeouts, and tracing metadata that excludes raw content.
- Replace byte estimates with the selected foundation model's exact tokenizer; validate maximum token budget.
- Add tenant-partitioned caches, mandatory revocation events, revalidation prior to tool execution, and nonces for decision replay.
- Design and execute adversarial tests covering content injection, subtle cross-tenant correlations, malicious conflicting evidence, replayed expired content, and compromised model responses.
- Review cloud data-processing agreements, retention, residency, and telemetry settings before third-party inference.
- Use short-lived scoped credentials stored in a secret manager; never commit provider tokens.

## Responsible claims

`ready` is an indication that **declared evidence identifiers** satisfy a deterministic policy. It is not proof that the evidence is complete, true, causally relevant, or safe to act on. Those properties require verification outside this MVP and constitute the core research plan.
