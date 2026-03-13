# Enterprise Deployment Guide (Kubernetes)

This guide explains how to deploy the Secure MCP Gateway into a customer Kubernetes cluster using the provided manifests.

## Prerequisites
*   A running Kubernetes Cluster.
*   (Recommended) A Redis instance (`redis-master:6379`) for distributed rate limiting and caching across multiple gateway replicas.
*   (Optional) An OPA Service running in the cluster if using `policy_type: "opa"`.

## Architecture Overview

1.  **Deployment**: Runs `secure-mcp-gateway` pods. It is configured out-of-the-box for high availability (`replicas: 3`).
2.  **ConfigMap**: Stores `config.yaml` and `dlp_rules.json`. The Gateway uses **Hot-Reloading**. If an admin updates this ConfigMap, the Gateway automatically detects the change without dropping active SSE or HTTP connections.
3.  **Service**: Exposes the Gateway internally to cluster agents or externally via LoadBalancer/Ingress.

## 1. Configure the Gateway
Edit `deploy/k8s/configmap.yaml`:

*   **Redis**: Ensure the `redis.addr` points to your cluster's Redis service.
*   **Upstreams**: Add the actual MCP servers you want to proxy in the `upstreams` list. Provide their internal cluster DNS names (e.g., `http://my-tool-adapter.namespace.svc.cluster.local:9090`).
*   **Policy**: If using OPA, ensure the `opa.server_url` points to your OPA sidecar or dedicated deployment.

## 2. Deploy to Kubernetes

Create the `mcp-system` namespace if it does not exist:
```bash
kubectl create namespace mcp-system
```

Apply the manifests:
```bash
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
```

## 3. Verify Deployment

Check the pods are running and healthy:
```bash
kubectl get pods -n mcp-system -l app=secure-mcp-gateway
```

Check the logs to ensure configuration and Redis connected successfully:
```bash
kubectl logs -n mcp-system deployment/secure-mcp-gateway
```
You should see output similar to:
`INFO Connected to Redis addr=redis-master:6379 db=0`
`INFO Server listening addr=:8080`

## 4. Exposing to Agents
Agents in other namespaces can reach the gateway at:
`http://secure-mcp-gateway.mcp-system.svc.cluster.local`

If you need external access (e.g., from agents outside the cluster), you should configure an **Ingress** resource pointing to the `secure-mcp-gateway` Service on port `80`.

## Updating Configuration (Hot Reload)
To add a new upstream or change rate limits:
1. Update `deploy/k8s/configmap.yaml`.
2. Apply the change: `kubectl apply -f deploy/k8s/configmap.yaml`.
3. Wait ~10 seconds. The pods will automatically reload the new configuration.
