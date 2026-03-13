# Build Stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/secure-mcp-gateway ./cmd/gateway

# Final Stage
FROM gcr.io/distroless/static-debian12

WORKDIR /app

COPY --from=builder /app/secure-mcp-gateway .
COPY --from=builder /app/config.yaml .
# Copy policy.json if it acts as default, though config maps it
COPY --from=builder /app/policy.json .

EXPOSE 8080

ENTRYPOINT ["./secure-mcp-gateway"]
