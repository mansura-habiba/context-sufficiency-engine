# CSE JSON contract v0.1

`cse compile request.json` accepts a single object. The Python API uses the same shape via `CompilationRequest.parse`.

## Request fields

| Field | Required | Meaning |
|---|---|---|
| `task` | Yes | Task statement; max 20,000 characters |
| `principal.tenant` / `.subject` | Yes | **Trusted caller-supplied** authenticated tenant and actor |
| `principal.clearance` | No | `public`, `internal` (default), `confidential`, `restricted` |
| `principal.scopes` | No | Array of **trusted** scopes |
| `task_classification` | No | Egress sensitivity, defaults to `internal` |
| `budget_tokens` | No | Integer 64–100,000, default 2,048; currently heuristic not exact |
| `items` | No | Array of evidence, capped by policy at 1,000 |
| `requirements` | No | Array of declared evidence coverage constraints |
| `pinned_ids` | No | IDs that must be included with their complete dependencies |

### Evidence item

Required: `id`, `tenant`, `title`, `content`, `source`. Optional fields:

| Field | Meaning |
|---|---|
| `version` | Source version string, default `1` |
| `sha256` | Lowercase 64-character SHA-256 of UTF-8 content, required by default |
| `classification` | `public`, `internal` (default), `confidential`, `restricted` |
| `visibility` | `tenant` (default), `restricted` |
| `allowed_subjects` / `allowed_scopes` | Optional ACL grants; when nonempty, either matching subject or matching scope grants access |
| `dependencies` | All referenced context IDs required atomically |
| `conflicts_with` | Context IDs that cannot appear in the same bundle |
| `tags` | Advisory relevance hints |
| `not_before` / `expires_at` | RFC 3339 / ISO 8601 strings with explicit timezone |

Even public-classified items are tenant-bound. `visibility=restricted` with no grants is denied. When both allowed subjects and scopes are specified, a grant by either is sufficient (logical OR). The gateway must enforce finer policies if both must be satisfied.

### Requirements

`{"id": "has-signal", "any_of": ["signal-a", "signal-b"], "min_count": 1}` means at least one *distinct* listed evidence ID must be selected. `min_count=2` means at least two distinct IDs. A requirement is **declarative**; it cannot detect an undeclared missing topic or unknown document.

## Result

| Field | Meaning |
|---|---|
| `status` | `ready`, `unverified`, `blocked` |
| `requirement_coverage` | `declared_requirements_met`, `not_evaluated`, or `not_met` |
| `context_json` | JSON string with `untrusted_evidence` array; `null` when blocked |
| `context_sha256` | SHA-256 of emitted JSON string; `null` when blocked |
| `provenance_manifest` | Authorized selected IDs, source, version, digest; empty when blocked |
| `selected_ids` | Authorized selected evidence IDs |
| `deferred_ids` | Authorized but unselected IDs (not unfiltered dataset IDs) |
| `missing_requirements` | Opaque labels derived only from requirements/pins the caller explicitly supplied |
| `excluded_counts` | Aggregated security/integrity/dependency exclusion reasons, no rejected IDs |
| `budget_tokens` / `estimated_tokens` | Requested and estimated output cost; *not an exact tokenizer count* |
| `scorer` / `degraded` | Scorer used and fallback/local-mixing indicator |

`context_json` is a string for direct use as a prompt data attachment. It is not executable instructions. The caller must not forward the entire result, especially audit metadata, to an LLM as if it were authoritative system instructions.

## Extending the protocol

CSE has no persistence. To refresh, revoke, or expand evidence, construct a **new request** with the currently authorized evidence set and pin IDs that should be loaded. Treat every compile result as a snapshot, not a continuously valid capability. For critical workflows, check permissions and evidence freshness again immediately before side effects.
