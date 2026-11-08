# Context Sufficiency Engine (CSE)

**Secure context compilation for AI systems.** A small, dependency-free Python engine that builds an authorized, evidence-aware context bundle under a token budget. A fast System One decision model or a small locally trained scorer can rank *eligible* evidence; neither can override security or declared evidence requirements.

> **Status: research MVP (v0.1.0).** Works offline with no GPU, Docker, model API, database, or inference server. It is not a proven context-sufficiency predictor, enterprise authorization service, or production-certified prompt-injection defense.

## Quick start

Requires Python 3.11+. From a clone:

```bash
python -m pip install -e .
cse compile examples/incident.json
cse benchmark examples/eval_cases.json
python -m unittest discover -s tests -v
```

No network call occurs unless Cloudflare inference is expressly enabled.

### What happens when you compile?

```text
Task + trusted principal + candidate evidence + declared requirements
          |
          v
  POLICY FILTER (tenant, ACL, clearance, time, digest)
          |
          v
  RANKER (local lexical / learned linear / hosted Clef)
          |
          v
  COMPILER (dependencies, conflicts, evidence cover, token budget)
          |
          v
  Context JSON + provenance manifest + status + deferred IDs
```

`status: "ready"` means **your declared evidence requirements have been satisfied**. It does **not** imply that the context is semantically sufficient to answer the task or that any action is authorized. When there are no requirements, the status is `unverified`. When mandatory evidence is missing, unauthorized, conflicted, expired, or over budget, the compiler returns `blocked` and `context_json: null`.

## What is implemented

| Capability | Status | Boundary |
|---|---|---|
| Policy-first tenant, clearance, scope, subject, expiry checks | Implemented | Runs before every scorer |
| SHA-256 integrity check | Implemented | Must be matched to an independently trusted manifest to prove source authenticity |
| Dependency closure | Implemented | Required evidence and transitive dependencies are selected atomically |
| Declared evidence coverage | Implemented | `any_of` + `min_count`, not a learned semantic sufficiency judgment |
| Declared conflict exclusion | Implemented | Conflict metadata supplied by ingestion; not automatically inferred |
| Budgeted context compiler | Implemented | Approximate token budget; real model tokenizer still needed |
| Deferred evidence identifiers | Implemented | Eligible IDs only; caller can recompile to expand |
| Audit provenance manifest + output hash | Implemented | No persistent storage by default |
| Local lexical scoring | Implemented | Dependency-free baseline |
| Tiny CPU-trained hashed linear scorer | Experimental | JSON weights, no pickle, offline training |
| Cloudflare Clef / Clef-flash | Optional integration | Explicit egress opt-in, credentials, classification ceiling |
| CI, security unit tests, case replay benchmark | Implemented | Not a downstream LLM correctness benchmark |
| Semantic sufficiency model, learned dependency detection, revocation events | Research backlog | Not claimed as implemented |

## Example: Python library

```python
import json
from pathlib import Path
from cse import CompilationRequest, ContextCompiler

body = json.loads(Path("examples/incident.json").read_text())
request = CompilationRequest.parse(body)  # principal is trusted ONLY in this local demo
result = ContextCompiler().compile(request)

print(result.status, result.selected_ids, result.estimated_tokens)
if result.status == "ready":
    # Gate execution with an INDEPENDENT policy decision. Evidence is untrusted data.
    print(result.context_json)
```

### Minimal request format

```json
{
  "task": "Investigate checkout failure",
  "task_classification": "internal",
  "budget_tokens": 1024,
  "principal": {
    "tenant": "acme", "subject": "alice", "clearance": "internal",
    "scopes": ["incident.read"]
  },
  "items": [
    {
      "id": "alert-1", "tenant": "acme", "title": "Checkout error alert",
      "content": "Checkout API reported 5xx errors at 10:53 UTC.",
      "source": "monitoring://alerts/1", "version": "1",
      "sha256": "<64-character lowercase sha256 of the content>"
    }
  ],
  "requirements": [{"id": "has-monitoring-evidence", "any_of": ["alert-1"]}]
}
```

`sha256` in this illustrative snippet must be computed from the exact content. Use `cse.digest(content)` at **trusted ingestion**, retain that digest in a protected manifest, and compare it again during compilation. A hash supplied by the same compromised source does not authenticate that source.

Detailed fields and result semantics: [Input / output contract](docs/protocol.md).

## Optional: small trainable CPU scorer

The included learner is a hashed bag-of-words logistic model. It is intentionally tiny; it is **not** a fine-tuned Clef, a transformer encoder, or a demonstrated superior retrieval method.

```bash
cse train examples/labels.jsonl --output /tmp/cse-linear.json
cse compile examples/incident.json --scorer linear --model-file /tmp/cse-linear.json
cse benchmark examples/eval_cases.json --scorer linear --model-file /tmp/cse-linear.json
```

The example labels are synthetic training data. Their training accuracy is not a credible estimate of generalization. Use independent task families and downstream LLM outcomes for evaluation.

## Optional: Cloudflare Clef-flash

CSE supports the published Workers AI System One `noul` request shape; no hosted credentials are included. **External scoring is disabled by default.** Even with egress enabled, only evidence at or below the configured classification ceiling may be sent. Evidence outside that ceiling is scored locally.

```bash
export CLOUDFLARE_ACCOUNT_ID='your-account-id'
export CLOUDFLARE_API_TOKEN='your-scoped-api-token'
# Use an approved request where task_classification and shareable items are "public":
cse compile path/to/approved-public-request.json \
  --scorer clef-flash \
  --allow-external-scoring \
  --external-max-classification public
```

The default example is **internal**, and is intentionally blocked from cloud egress unless an enterprise security authority has approved a policy change. Do not relabel sensitive data merely to make a model call work. The caller must derive the task classification and principal from a trusted gateway, not from user-supplied headers or JSON.

The Clef adapter is contract-tested with synthetic responses, but live credentials and hosted inference have **not** been tested in this repository. Current model contract: [Cloudflare Clef-flash docs](https://developers.cloudflare.com/ai/models/%40cf/cloudflare/clef-flash/). Model versions, provider limits, and privacy terms should be revalidated before production deployment.

## Where it belongs

Embed `ContextCompiler` inside a **trusted** gateway (for example MCP Composer) after authentication and authorization, but before the target model call. The gateway must own principal derivation, source provenance verification, action authorization, logging controls, and external egress approval. CSE does not expose an unauthenticated HTTP API and does not persist context.

- [Architecture and alternatives](docs/architecture.md)
- [Security model and known gaps](docs/security.md)
- [Input / output contract](docs/protocol.md)
- [Evaluation and research plan](docs/research-plan.md)
- [Security reporting](SECURITY.md)

## Roadmap

1. Add task-outcome replay and omitted-evidence ablation tests with a real target LLM (hold out task families).
2. Train a 150M–500M parameter encoder with independent admission / dependency / refresh / insufficiency heads, only if it beats lexical and cheap learned baselines.
3. Add signed provenance manifests and a revocation event contract for long-lived workflows.
4. Add a gateway adapter with trusted claims, tracing, and a real tokenizer integration.
5. Benchmark managed cloud costs, calibration, p95 latency, evidence omission, attack success, and cost per *successful* task.

CSE is licensed under Apache-2.0. See [LICENSE](LICENSE).
