# Secure MCP Gateway - Walkthrough

## Prerequisites
*   Go 1.22+
*   The original demo `mcp-mock` running (optional, but good for end-to-end test).

## 1. Start the Upstream Mock (Optional)
In the parent directory (`/Users/Sauransh.Singh/Downloads/mcp-vpn-poc-docker-mtls-fixed`), run:
```bash
docker compose up mcp-mock
```
This starts a mock MCP server at `http://localhost:9090`.

## 2. Configure the Gateway
The `config.yaml` is pre-configured to point to this mock:
```yaml
upstreams:
  - id: "demo-mcp"
    base_url: "http://localhost:9090"
    auth_type: "none"
```

## 3. Run the Gateway
From the `secure-mcp-gateway` directory:
```bash
go run cmd/gateway/main.go --config config.yaml
```
You should see:
```text
INFO Starting Secure MCP Gateway addr=:8080
INFO Server listening addr=:8080
```

## 4. Test Verification
### Health Check
```bash
curl http://localhost:8080/healthz
# Output: OK
```

### MC Protocol Request (Proxy)
Note: We are using `X-API-Key: secret-admin-key` which maps to `admin` role (allowed tools: `demo-tool`, `echo`).

```bash
curl -X POST http://localhost:8080/mcp/demo-mcp \
  -H "X-API-Key: secret-admin-key" \
  -d '{
    "jsonrpc": "2.0",
    "method": "echo.call",
    "params": {"message": "Hello sk-12345"},
    "id": 1
  }'
```

**Expected Result (with DLP Redaction):**
The output should contain `Hello sk-[REDACTED]`.
*Note: This now uses a Streaming DLP scanner, meaning it handles large responses without holding them entirely in memory.*



## 5. Security Tests
Try using a blocked keyword:
```bash
curl -X POST http://localhost:8080/mcp/demo-mcp \
  -H "X-API-Key: secret-admin-key" \
  -d '{
    "jsonrpc": "2.0",
    "method": "echo.call",
    "params": {"message": "rm -rf /"},
    "id": 1
  }'
```
**Expected Result:**
HTTP 200 (JSON-RPC Error) with message `Security Block: blocked keyword: rm -rf`.

## 6. Dynamic Authentication (Header Injection)
To route to real-world cloud MCP servers (e.g., GitHub, Netskope) without exposing service credentials to the AI Agent, configure injection rules in `config.yaml`.
**Example (Injecting a Bearer Token via Service Account):**
```yaml
upstreams:
  - id: "github-remote"
    base_url: "https://api.githubcopilot.com/mcp"
    auth_type: "bearer"
    auth:
      token: "${GITHUB_SERVICE_PAT}" # Secret expanded from gateway's OS env vars
```

**Example (Agent Pass-Through Authentication):**
```yaml
upstreams:
  - id: "github-user"
    base_url: "https://api.githubcopilot.com/mcp"
    auth_type: "forward"
    auth:
      header: "Authorization" # Forwards the Authorization header provided by the Agent
```

## 7. Configuring mTLS (Real Server Mode)
To use mTLS, update `config.yaml`:
```yaml
server:
  addr: ":8443"
  mtls: true
  cert_file: "/path/to/server.pem"
  key_file: "/path/to/server.key"
  ca_file: "/path/to/ca.pem" # For verifying clients (Agents)

upstreams:
  - id: "secure-mcp"
    base_url: "https://secure-mcp-server:9443"
    client_cert_file: "/path/to/client.pem"
    client_key_file: "/path/to/client.key"
    ca_file: "/path/to/upstream-ca.pem" # For verifying the upstream server
    ca_file: "/path/to/upstream-ca.pem" # For verifying the upstream server
```

## 8. Configuring OPA (Policy Engine)
To use Open Policy Agent instead of local `policy.json`:
1.  Run OPA Server: `opa run -s` (on port 8181 default)
2.  Update `config.yaml`:
```yaml
server:
  addr: ":8080"
  policy_type: "opa"
  opa_url: "http://localhost:8181/v1/data/mcp/allow"
```
3.  Load Policy into OPA:
```bash
curl -X PUT http://localhost:8181/v1/policies/mcp \
  --data-binary @opa-policy.rego
```

