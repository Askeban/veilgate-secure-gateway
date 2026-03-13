#!/bin/bash
# scripts/update_policy.sh

# Resolve script directory to find policy.rego reliably
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
POLICY_FILE="$DIR/../policy.rego"

echo "📢 Updating OPA Policy from $POLICY_FILE..."

# Push the policy and capture output
RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "http://localhost:8181/v1/policies/mcp" --data-binary @"$POLICY_FILE")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" -eq 200 ]; then
    echo "✅ Success: Policy updated successfully!"
else
    echo "❌ Failed to update policy. HTTP Code: $HTTP_CODE"
    echo "Response: $BODY"
    exit 1
fi
