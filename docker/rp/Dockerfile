# Build stage
FROM golang:1.25.6-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk --no-cache add ca-certificates

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /rp-server ./rp/cmd

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy templates first (before binary)
COPY rp/templates/ ./rp/templates/

# Copy binary from builder
COPY --from=builder /rp-server .

# Expose port (Cloud Run uses PORT env var)
EXPOSE 8080

# Run the binary
CMD ["./rp-server"]
