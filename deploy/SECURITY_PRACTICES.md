# Securing a Multi-Container AI System on Azure (AKS + Service Bus)

Security practices for the deployment Modules 08–09 build: several Docker containers,
orchestrated by Kubernetes on AKS, communicating through Service Bus topics, and
serving users over the network. Every practice points to the file in `deploy/` that
implements it, so each can be read, copied and tested.

The system: a public **gateway** (runs the guarded pipeline from this repo) publishes a
`TicketRouted` message to the `tickets.routed` topic; a **billing worker** consumes its
filtered subscription.

```
 Internet ──443/TLS──► Ingress (NGINX, app routing) ──8080──► gateway pods ──5671──► Service Bus (private endpoint)
                                                                  │                          │
                                                                  └──443──► Key Vault (PE)   └──5671──► worker-billing pods
                                                                                                        (no inbound port)
```

## 1. Ports: expose one, and only one

| Port | Where | Exposed to | Why |
|---|---|---|---|
| **443** | Ingress controller | **Internet** (the only public port) | HTTPS; TLS terminates here with a Key Vault certificate |
| 80 | Ingress controller | Internet | Only to redirect to 443 (`force-ssl-redirect`) |
| 80 → 8080 | `gateway` Service (ClusterIP) | Ingress controller only | ClusterIP is unreachable from outside the cluster |
| 8080 | gateway container | NetworkPolicy: ingress controller only | Unprivileged port, so the process never needs root |
| — | worker | Nothing | It pulls from Service Bus; no Service, no open port |
| 5671 | egress to Service Bus | Private endpoint subnet | AMQP over TLS (443 if AMQP-over-WebSockets) |
| 443 | egress to Key Vault / Entra ID / LLM | Private endpoint subnet; firewall FQDN allowlist | |
| 53 | egress to CoreDNS | kube-system only | Name resolution |
| API server | AKS control plane | Your admin IPs only | `--api-server-authorized-ip-ranges`, or a private cluster |

Rules that follow from the table:

- Application Services are **ClusterIP**. No `LoadBalancer` or `NodePort` except the one ingress. → `k8s/30-services.yaml`
- Route only the paths users need. `/health` and `/ready` are for the kubelet, not the internet. → `k8s/40-ingress.yaml` (`pathType: Exact` on `/predict`)
- A component that only consumes messages gets no Service and no inbound port at all. → `worker-billing`

## 2. Container images

| Practice | Where |
|---|---|
| Multi-stage build; build tools never reach the runtime image | `Dockerfile` |
| Slim base pinned by version, and by **digest** in CI | `Dockerfile`, `k8s/20-deployments.yaml` (`image: …@sha256:`) |
| Non-root numeric UID (10001), so Kubernetes can verify `runAsNonRoot` | `Dockerfile` |
| No secrets or keys in the image or its layers | `Dockerfile`; identity comes from workload identity at runtime |
| Only needed code copied in | `.dockerignore` |
| Private registry, no admin account, nodes pull with managed identity | `azure/cluster.sh` (`--admin-enabled false`, `--attach-acr`) |
| Vulnerability scanning of registry images | Defender for Containers (`--enable-defender`) |

Verified locally: the image runs as UID 10001 and fails to write anywhere on a read-only root filesystem.

## 3. Pods and the cluster

| Practice | Where |
|---|---|
| Pod Security Admission **restricted** enforced on the namespace: the API server rejects root, privilege escalation, extra capabilities, missing seccomp | `k8s/00-namespace.yaml` |
| `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, drop `ALL` capabilities, `seccompProfile: RuntimeDefault` | `k8s/20-deployments.yaml` |
| Only writable path is a small in-memory `/tmp` | `k8s/20-deployments.yaml` |
| CPU/memory requests **and limits** | `k8s/20-deployments.yaml` |
| No Kubernetes API token in pods that don't call the API | `automountServiceAccountToken: false` |
| One service account per component | `k8s/10-serviceaccounts.yaml` |
| Entra ID sign-in and Azure RBAC for `kubectl`; no local admin account | `--enable-aad --enable-azure-rbac --disable-local-accounts` |
| Automatic security patching of Kubernetes and node images | `--auto-upgrade-channel patch --node-os-upgrade-channel NodeImage` |
| Cluster-wide policy enforcement and audit | `--enable-addons azure-policy` |

## 4. Identity and secrets: prefer no secrets

1. **Workload identity for every Azure call.** Each component's service account is federated
   to its own managed identity (`azure/cluster.sh`), and pods get short-lived Entra ID tokens.
   Service Bus, Key Vault, ACR and Azure OpenAI all accept these, so none of them needs a key.
2. **Least privilege per identity.** The gateway gets *Data Sender* on one topic; the worker gets
   *Data Receiver* on one subscription (`azure/servicebus.bicep`), and *Key Vault Secrets User*
   goes to the gateway only. A compromised pod can do exactly one component's job.
3. **Where a secret is unavoidable** (e.g. a third-party LLM API key): keep it in Key Vault and
   mount it as a read-only file through the CSI driver (`k8s/60-secretproviderclass.yaml`),
   not a Kubernetes Secret or an environment variable.
4. **Block the node's identity.** Egress to the instance metadata endpoint `169.254.169.254`
   is excluded (`k8s/50-networkpolicies.yaml`), so a pod cannot borrow the node's credentials.

## 5. Network

| Practice | Where |
|---|---|
| Default-deny all ingress and egress in the namespace, then allow each needed flow | `k8s/50-networkpolicies.yaml` |
| Network policy enforced by Cilium | `--network-dataplane cilium` |
| PaaS services (Service Bus, Key Vault, ACR) on **private endpoints**, public access disabled | `azure/servicebus.bicep`, `azure/cluster.sh` |
| Internet egress through Azure Firewall with an FQDN allowlist (Entra ID, the LLM endpoint) | Noted in `50-networkpolicies.yaml`; NetworkPolicy is IP-only |
| Control plane restricted to admin IPs or made private | `--api-server-authorized-ip-ranges` |
| WAF in front of the ingress for internet-facing production | Application Gateway for Containers / Front Door (noted in `40-ingress.yaml`) |

## 6. Messaging (Service Bus topics)

| Practice | Where |
|---|---|
| **Local auth disabled**: SAS keys and connection strings do not work | `disableLocalAuth: true` in `azure/servicebus.bicep` |
| Private endpoint only; TLS 1.2 minimum | `azure/servicebus.bicep` |
| Sender and receiver roles scoped to one topic / one subscription | `azure/servicebus.bicep` |
| Validate the message schema **before publishing and after receiving**; a queue is a trust boundary too | `app/messaging.py` (Module 05 schema) |
| Invalid, oversized or unparseable messages are dead-lettered with a reason, not crashed on | `app/messaging.py` |
| Bounded retries (`maxDeliveryCount`), then dead-letter; monitor the dead-letter queue | `azure/servicebus.bicep` |
| Duplicate detection, plus idempotent consumers keyed on `message_id` | `azure/servicebus.bicep`, `app/messaging.py` |
| Subscription filters on a publisher-set property, so a worker only sees its queue | `azure/servicebus.bicep` (`SqlFilter`) |
| Correlation ID carried end to end for tracing and audit (STRIDE: repudiation) | `app/messaging.py` |

## 7. The application at the edge

The gateway process adds its own checks, because the ingress is not the only thing that
can reach it (a misconfigured policy, another pod):

- body size cap, JSON-only, required fields type-checked → `app/server.py`
- API key in a header, never the URL (URLs are logged); per-tenant rate limit and budget cap → `app/server.py`, `ticketbot/guardrails/architectural.py`
- generic error messages to the client, details only in server logs; no `Server` banner → `app/server.py`
- the input/output/architectural guardrails of this repo on every request → `ticketbot/`

Rate limiting is layered: per client IP at the ingress (`limit-rps`), per tenant in the app.

## 8. Cost and monitoring

- Container Insights / Log Analytics for pod logs; Service Bus and Key Vault diagnostic logs.
- Alerts on: dead-letter queue depth, 401/429/422 rates at the gateway, Key Vault access denials.
- A subscription **budget with alerts**: the last line of defense against denial of wallet (see
  `azure/cluster.sh`), in addition to the per-tenant budget cap in the application.

## How these files were checked

| Check | Result |
|---|---|
| `docker build`, then run with `--read-only --cap-drop ALL --security-opt no-new-privileges` | runs as UID 10001; root filesystem not writable; endpoints return 200 / 401 / 413 / 415 / 422 / 429 as designed |
| `kubeconform -strict` on `k8s/` | 12 resources valid; the Key Vault `SecretProviderClass` CRD skipped (no public schema) |
| `az bicep build` on `azure/servicebus.bicep` | compiles (10 resources) |
| `bash -n azure/cluster.sh`, and every `az aks create` flag checked against `az` 2.90.0 | ok |

Not done here: deploying to a live Azure subscription. `cluster.sh` creates billable resources;
review it before running.
