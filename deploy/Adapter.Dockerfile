# Build Adapter
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -o adapter ./cmd/adapter

# Final Image
# We use node:20-slim because most MCP servers are Node.js based (npx ...)
# If you need Python servers, use python:3.11-slim or a custom base
FROM node:20-slim

WORKDIR /app
COPY --from=builder /app/adapter /app/adapter

# Default entrypoint
ENTRYPOINT ["/app/adapter"]
