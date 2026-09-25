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

The `deploy/` folder shows how to run this system as multiple Docker containers on Azure
Kubernetes Service (AKS), communicating through Service Bus topics and serving users over
HTTPS. `deploy/SECURITY_PRACTICES.md` explains *why* each practice matters and links it to
the file that implements it; this section explains *what is where* and *how to use it*.

### Architecture

```
 Internet ──443/TLS──► Ingress (NGINX, app routing) ──8080──► gateway pods ──5671──► Service Bus topic
                                                                  │                  "tickets.routed"
                                                                  │                        │ subscription "billing"
                                                                  └──443──► Key Vault      ▼
                                                                                    worker-billing pods
                                                                                    (no inbound port)
```

- **gateway** is the only component users can reach. It runs the guarded pipeline from this
  repo (`ticketbot/`) behind a small HTTP server and publishes a `TicketRouted` message.
- **worker-billing** reads only the `billing` subscription. Nothing calls it, so it has no
  Service and no open port.
- **Service Bus** and **Key Vault** are reachable only through private endpoints inside the
  virtual network. Neither has a public address.

### Files

| File | What it does | Key security settings |
|---|---|---|
| `deploy/Dockerfile` | Builds the gateway image from the repo root | Multi-stage build; non-root UID 10001; listens on 8080; no secrets in any layer |
| `.dockerignore` | Keeps tests, logs, attack data and manifests out of the image | Smaller image, less to scan, nothing sensitive copied |
| `deploy/app/server.py` | HTTP front end: `GET /health`, `GET /ready`, `POST /predict` | 8 KB body cap; JSON only; API key in a header; generic errors; no `Server` banner; per-tenant rate limit and budget cap |
| `deploy/app/messaging.py` | Service Bus publisher and consumer | Entra ID sign-in, no connection strings; schema check before send and after receive; dead-letter bad messages; ignores duplicates |
| `deploy/app/schema/` | The Module 05 `TicketRouted` schema and its validator | The same contract is enforced in the eval harness and in production |
| `deploy/k8s/00-namespace.yaml` | The `ticketbot` namespace | Pod Security Admission `restricted`: the cluster rejects root or privileged pods |
| `deploy/k8s/10-serviceaccounts.yaml` | One service account per component | Each linked to its own Azure managed identity; no Kubernetes API token mounted |
| `deploy/k8s/20-deployments.yaml` | gateway (2 replicas) and worker-billing | Read-only filesystem; all capabilities dropped; CPU/memory limits; health probes; image pinned by digest |
| `deploy/k8s/30-services.yaml` | Internal address for the gateway | ClusterIP only; no `LoadBalancer` or `NodePort` |
| `deploy/k8s/40-ingress.yaml` | The single public entry point | HTTPS with a Key Vault certificate; HTTP→HTTPS redirect; only `/predict` routed; body cap; per-IP rate limit |
| `deploy/k8s/50-networkpolicies.yaml` | Pod-to-pod and outbound traffic rules | Default deny all; allow only DNS, ingress→gateway, and egress to private endpoints and HTTPS; node metadata endpoint blocked |
| `deploy/k8s/60-secretproviderclass.yaml` | Mounts a Key Vault secret as a file | For unavoidable third-party keys only; read-only file, not an environment variable |
| `deploy/azure/cluster.sh` | Creates the network, registry, AKS cluster, Key Vault and identities | Entra ID + Azure RBAC for `kubectl`; no local admin; API server IP allowlist; workload identity; Cilium network policy; Defender; automatic patching |
| `deploy/azure/servicebus.bicep` | Service Bus namespace, topic, subscriptions, access and private endpoint | Shared-key access disabled; TLS 1.2; private endpoint only; send/receive roles scoped to one topic or subscription; retry cap then dead-letter |

### Ports

| Port | Where | Who can reach it |
|---|---|---|
| 443 | Ingress controller | The internet (the only public port) |
| 80 | Ingress controller | The internet, only to redirect to 443 |
| 80 → 8080 | `gateway` Service → gateway container | Only the ingress controller (NetworkPolicy) |
| none | worker-billing | Nobody; it only reads from Service Bus |
| 5671 / 443 out | gateway, worker → Service Bus, Key Vault | Private-endpoint subnet `10.20.2.0/24` only |
| 443 out | gateway, worker → Entra ID sign-in, LLM API | Through Azure Firewall with a host-name allowlist |
| 53 out | all pods → CoreDNS | `kube-system` only |

### Try the container locally

Build from the repo root, then run it with the same restrictions Kubernetes applies:

```bash
docker build -f deploy/Dockerfile -t ticketbot:dev .
docker run -d --name tb -p 127.0.0.1:18080:8080 \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges ticketbot:dev

docker exec tb id -u                               # 10001, not root
curl -s http://127.0.0.1:18080/health              # {"status": "ok"}
curl -s -H 'Content-Type: application/json' -H 'X-API-Key: acme-key-123' \
  -d '{"customer_id":"c1","text":"I was charged twice this month."}' \
  http://127.0.0.1:18080/predict                   # 200, a drafted reply
docker rm -f tb
```

Expected responses from `POST /predict`:

| Request | Status |
|---|---|
| Valid key and an ordinary ticket | 200 |
| Missing or unknown `X-API-Key` | 401 |
| Oversized body (> 8 KB) | 413 |
| Content type other than `application/json` | 415 |
| Blocked by a guardrail (e.g. prompt injection) | 422 |
| Rate limit or daily budget exceeded | 429 |
| Anything unexpected on the server | 500, with details only in the server log |

The demo API keys (`acme-key-123`, `globex-key-456`) are hard-coded in
`ticketbot/pipeline.py` for local testing only. In a real deployment, keys come from a
secret store or you use Entra ID tokens instead.

### Check the manifests and templates without deploying

```bash
# Kubernetes schema validation (runs in a container, nothing to install)
docker run --rm -v "$PWD/deploy/k8s:/k8s:ro" ghcr.io/yannh/kubeconform:latest \
  -strict -summary -ignore-missing-schemas /k8s

# Compile the Service Bus template
az bicep build --file deploy/azure/servicebus.bicep --stdout > /dev/null

# Syntax-check the cluster script
bash -n deploy/azure/cluster.sh
```

### Deploying to Azure

Everything below creates **billable** resources. Read `deploy/azure/cluster.sh` before
running it.

1. **Create the infrastructure:** `az login`, then run `deploy/azure/cluster.sh`. It creates the
   resource group, virtual network, container registry, AKS cluster, Key Vault, one managed
   identity per component, and the Service Bus namespace (via `servicebus.bicep`).
2. **Build and push the images** to your registry, then note each image's digest:
   `az acr build -r <ACR_NAME> -t ticketbot-gateway:1.0 -f deploy/Dockerfile .`
3. **Store secrets and the TLS certificate in Key Vault:** the `llm-api-key` secret (only if
   your LLM provider does not accept Entra ID) and the `tickets-tls` certificate.
4. **Fill in the placeholders** in `deploy/k8s/`:

   | Placeholder | Where to get it |
   |---|---|
   | `<ACR_NAME>`, `<DIGEST>` | Your registry name; the digest printed by `az acr build` |
   | `<GATEWAY_IDENTITY_CLIENT_ID>`, `<WORKER_BILLING_IDENTITY_CLIENT_ID>` | `az identity show -g rg-ticketbot -n id-gateway --query clientId -o tsv` (and `id-worker-billing`) |
   | `<SB_NAMESPACE>` | The `namespaceName` passed to `servicebus.bicep` |
   | `<KEYVAULT_NAME>`, `<TENANT_ID>` | Your Key Vault name; `az account show --query tenantId -o tsv` |
   | `tickets.example.com` | Your DNS name for the service |
   | `10.20.2.0/24` | Your private-endpoint subnet, if you changed it in `cluster.sh` |

5. **Apply the manifests** in order (the file numbers set it):
   `az aks get-credentials -g rg-ticketbot -n aks-ticketbot && kubectl apply -f deploy/k8s/`
6. **Verify:** `kubectl -n ticketbot get pods` shows all pods running; a request to
   `https://tickets.example.com/predict` returns 200; `/health` from outside returns 404,
   because only `/predict` is routed.

### What has and has not been verified

| Verified here | Not verified |
|---|---|
| Image builds; runs as UID 10001 on a read-only filesystem; every status code in the table above | A live deployment to Azure |
| All 12 core Kubernetes resources pass `kubeconform -strict` | The Key Vault `SecretProviderClass` (no public schema to check against) |
| `servicebus.bicep` compiles (10 resources) | `worker-billing` image: the manifest references it, but only the gateway image is built here |
| Every `az aks create` flag exists in Azure CLI 2.90.0 | Azure Firewall and the subscription budget, which are described but not scripted |

Not included: the `THREAT_MODEL.md`, the guardrail implementation plan and the peer
pen-test reports. Each team writes those for its own system.
