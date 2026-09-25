#!/usr/bin/env bash
# Azure infrastructure for the ticket system, with the security-relevant flags explained.
# REVIEW AND EDIT BEFORE RUNNING: it creates billable resources. Names are placeholders.
# Requires: az CLI logged in, and permission to create role assignments.
set -euo pipefail

RG=rg-ticketbot LOC=eastus AKS=aks-ticketbot ACR=acrticketbot$RANDOM KV=kv-ticketbot-$RANDOM
SB=sb-ticketbot-$RANDOM VNET=vnet-ticketbot NS=ticketbot
MY_IP=$(curl -s https://api.ipify.org)        # your admin IP, for the API server allowlist

az group create -n $RG -l $LOC

# --- Network: separate subnets for nodes and for private endpoints ---------------------
az network vnet create -g $RG -n $VNET --address-prefixes 10.20.0.0/16 \
  --subnet-name snet-aks --subnet-prefixes 10.20.0.0/22
az network vnet subnet create -g $RG --vnet-name $VNET -n snet-private-endpoints \
  --address-prefixes 10.20.2.0/24          # the CIDR 50-networkpolicies.yaml allows egress to
AKS_SUBNET=$(az network vnet subnet show -g $RG --vnet-name $VNET -n snet-aks --query id -o tsv)

# --- Container registry: private images, no shared admin password ---------------------
az acr create -g $RG -n $ACR --sku Premium --admin-enabled false
# Premium enables private endpoints; add one and set --public-network-enabled false once
# your CI pushes from inside the network.

# --- AKS --------------------------------------------------------------------------------
# --enable-aad / --enable-azure-rbac / --disable-local-accounts : every kubectl user signs in
#     with Entra ID and is authorized by Azure RBAC; no shared admin kubeconfig exists.
# --api-server-authorized-ip-ranges : the control plane only answers your admin IPs
#     (or use --enable-private-cluster to take it off the internet entirely).
# --enable-oidc-issuer --enable-workload-identity : pods get Entra ID tokens for their own
#     managed identity; no secrets in the cluster for Azure access.
# --network-plugin azure --network-plugin-mode overlay --network-dataplane cilium :
#     enforces the NetworkPolicies in k8s/50-networkpolicies.yaml.
# --enable-addons azure-keyvault-secrets-provider,azure-policy : Key Vault CSI driver; Azure
#     Policy (Gatekeeper) to audit/deny non-compliant pods cluster-wide.
# --enable-defender : Microsoft Defender for Containers (runtime threat detection, image
#     vulnerability assessment for ACR).
# --enable-app-routing : managed NGINX ingress, the single public entry point.
# --auto-upgrade-channel patch --node-os-upgrade-channel NodeImage : security patches applied
#     without waiting for someone to remember.
# --enable-image-cleaner : removes unused (and possibly vulnerable) images from nodes.
# --attach-acr : nodes pull from ACR with their managed identity, no pull secrets.
az aks create -g $RG -n $AKS -l $LOC \
  --node-count 2 --node-vm-size Standard_D2s_v5 --vnet-subnet-id "$AKS_SUBNET" \
  --network-plugin azure --network-plugin-mode overlay --network-dataplane cilium \
  --enable-aad --enable-azure-rbac --disable-local-accounts \
  --api-server-authorized-ip-ranges "$MY_IP/32" \
  --enable-oidc-issuer --enable-workload-identity \
  --enable-addons azure-keyvault-secrets-provider,azure-policy \
  --enable-secret-rotation \
  --enable-defender \
  --enable-app-routing \
  --auto-upgrade-channel patch --node-os-upgrade-channel NodeImage \
  --enable-image-cleaner \
  --attach-acr $ACR \
  --generate-ssh-keys

OIDC=$(az aks show -g $RG -n $AKS --query oidcIssuerProfile.issuerUrl -o tsv)

# --- Key Vault: RBAC authorization, purge protection, no public network access --------
az keyvault create -g $RG -n $KV -l $LOC --enable-rbac-authorization true \
  --enable-purge-protection true --retention-days 90 --public-network-access Disabled
# Then add a private endpoint for it in snet-private-endpoints (same pattern as
# Service Bus in servicebus.bicep).

# --- One managed identity per component, federated to its Kubernetes service account --
for comp in gateway worker-billing; do
  az identity create -g $RG -n id-$comp
  az identity federated-credential create -g $RG --identity-name id-$comp -n fc-$comp \
    --issuer "$OIDC" --subject "system:serviceaccount:$NS:$comp" \
    --audiences api://AzureADTokenExchange
done
GW_PRINCIPAL=$(az identity show -g $RG -n id-gateway --query principalId -o tsv)
WK_PRINCIPAL=$(az identity show -g $RG -n id-worker-billing --query principalId -o tsv)

# Gateway may read secrets (not manage them) in this one vault; the worker gets nothing here.
az role assignment create --assignee-object-id "$GW_PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets User" --scope "$(az keyvault show -n $KV --query id -o tsv)"

# --- Service Bus: see servicebus.bicep (no SAS keys, private endpoint, per-topic RBAC) --
az deployment group create -g $RG --template-file "$(dirname "$0")/servicebus.bicep" \
  --parameters namespaceName=$SB vnetName=$VNET peSubnetName=snet-private-endpoints \
               gatewayPrincipalId="$GW_PRINCIPAL" workerBillingPrincipalId="$WK_PRINCIPAL"

# --- Cost guardrail: a subscription budget with an alert (denial of wallet, at the bill) -
# az consumption budget create ... or set it in the portal: Cost Management > Budgets.

echo "Next: put the identities' client IDs into k8s/10-serviceaccounts.yaml, then"
echo "  az aks get-credentials -g $RG -n $AKS && kubectl apply -f ../k8s/"
