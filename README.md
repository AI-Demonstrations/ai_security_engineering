# AI Security Engineering — Module 06 Examples

Runnable Python examples of the three guardrail layers the Module 06 deliverable asks
each team to implement and evidence: **input**, **output** and **architectural**. The
system is the Module 05 support-ticket router, extended with a reply-drafting step
that reads knowledge-base articles.

Everything runs offline with the Python standard library. The model is a deterministic
stand-in (`ticketbot/llm.py`) that behaves like a gullible real model, so every result is
free and repeatable. To test a real model, replace it with a client that has the same
`complete(messages, max_output_tokens)` signature.

## Quick start

```bash
python3 -m unittest discover -s tests -t . -v    # 42 tests
python3 eval_guardrails.py                       # attack/benign evaluation -> reports/
./run_evidence.sh                                # all evidence logs -> logs/
```

Tested on Python 3.9.

## Files

| Path | What it is |
|---|---|
| `ticketbot/pipeline.py` | The request path, with every guardrail switchable (`guarded=True/False`) so the same input can be run with and without protection |
| `ticketbot/guardrails/input_guard.py` | **Input** guardrail: size limit, Unicode normalization, base64 decoding, pattern checks; applied to the ticket and to retrieved articles |
| `ticketbot/guardrails/output_guard.py` | **Output** guardrail: system-prompt leak detection (canary), link allowlist, PII redaction, reply size limit |
| `ticketbot/guardrails/architectural.py` | **Architectural** guardrails: API-key auth, per-tenant rate limit, daily budget cap |
| `ticketbot/datastore.py` | Two-tenant data layer: `TicketStore` (hardened) and `VulnerableTicketStore` (teaching contrast) |
| `ticketbot/kb.py`, `llm.py`, `router.py` | Knowledge base (includes one poisoned article), stand-in model, keyword router |
| `attacks/attacks.jsonl` | 17 labeled attack inputs, each tagged with an OWASP LLM Top 10 item and a MITRE ATLAS ID |
| `attacks/benign.jsonl` | 66 legitimate tickets (the Module 05 golden set plus 6 that look like attacks) |
| `eval_guardrails.py` | Measures the guardrails the way Module 05 measures a model |
| `tests/` | One test file per layer, plus end-to-end and data-layer tests |
| `run_evidence.sh` | Writes the per-guardrail test logs and evaluation runs to `logs/` |

## Results (`reports/guardrail_eval.md`)

| Check | Unguarded | Guarded |
|---|---|---|
| Attacks that succeed (of 17) | 17 | 0 |
| Burst of 20 simultaneous requests | 20 processed | 5 processed |
| 200-request cost campaign | $262.57 | $0.50 (the daily cap) |
| Legitimate tickets blocked (of 66) | — | 1 (1.5%) |

Points worth discussing in class:

- **Defense in depth.** A paraphrased request gets past the input guard's patterns; the
  output guard catches the result because the canary token appears in the reply. Pattern
  matching is one layer, never the only one.
- **Indirect injection.** An innocent "When will my order ship?" triggers the poisoned
  article when unguarded. Guarded, the article is checked like user input and dropped.
- **False positives are a cost.** "You are now charging me twice" is blocked by the
  role-hijack pattern. Report the false-positive rate next to the block rate.
- **Architectural controls bound what text filters cannot.** The output-token cap and the
  daily budget cap limit spend no matter what the input says.

## How this maps to the deliverable

| Deliverable requirement | Example here |
|---|---|
| One input guardrail implemented, with test output showing a block | `input_guard.py`, `logs/test_input_guard.log` |
| One output guardrail implemented, with test output showing a block | `output_guard.py`, `logs/test_output_guard.log` |
| One architectural guardrail implemented, with test output showing a block | `architectural.py`, `logs/test_architectural.log` |
| Denial of wallet: cost cap and how it is enforced | `BudgetGuard` + output-token cap; campaign result in `reports/guardrail_eval.md` |

## Deploying securely on Azure (`deploy/`)

`deploy/SECURITY_PRACTICES.md` covers securing this system as multiple containers on AKS,
communicating over Service Bus topics: the port map (one public port), hardened image and
pods, workload identity instead of secrets, default-deny network policies, private
endpoints, and locked-down messaging. It links each practice to a working file:
`deploy/Dockerfile`, `deploy/app/` (HTTP server, secure Service Bus publisher/consumer),
`deploy/k8s/` (manifests), and `deploy/azure/` (cluster script, Service Bus Bicep).

Not included: the `THREAT_MODEL.md`, the guardrail implementation plan and the peer
pen-test reports. Each team writes those for its own system.
