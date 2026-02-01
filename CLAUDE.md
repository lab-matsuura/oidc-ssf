# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

### Development
- `make run` - Start all servers (IdP:8080, RP:8081, RP2:8082) in background
- `make run-idp` - Run IdP (OIDC Provider) on port 8080
- `make run-rp` - Run RP (OIDC Client, Push delivery) on port 8081
- `make run-rp2` - Run RP2 (OIDC Client, Poll delivery) on port 8082
- `make stop` - Stop all running servers
- `make demo` - Build and run full demo with browser auto-open

### Building and Testing
- `make build` - Build IdP, RP, and RP2 binaries to `bin/`
- `make test` - Run all tests
- `make fmt` - Format all Go code
- `make lint` - Run linter (requires golangci-lint)
- `make check` - Run fmt, lint, and test

### Database
- `make db-start` - Start PostgreSQL (docker compose)
- `make db-setup` - Complete setup for all DBs (migrate + generate code)
- `make db-migrate` - Create migrations from schema changes (all DBs)
- `make db-migrate-apply` - Apply pending migrations (all DBs)
- `make sqlc-gen` - Regenerate Go code from queries

### Dependencies
- `make deps` - Run go mod tidy and download

## Architecture Overview

This is an OIDC (OpenID Connect) + SSF (Shared Signals Framework) research implementation, organized as a monorepo:

```
ssf/
├── idp/                    # Identity Provider (OIDC Provider + SSF Transmitter)
│   ├── cmd/                # Entry point (main.go)
│   ├── internal/
│   │   ├── handler/        # OIDC/SSF HTTP handlers
│   │   ├── portal/         # Portal handlers (admin UI)
│   │   ├── provider/       # OIDC provider (ory/fosite)
│   │   ├── user/           # User service
│   │   └── storage/postgres/  # PostgreSQL storage + sqlc
│   ├── db/postgres/        # Schema and migrations
│   └── templates/          # HTML templates
├── rp/                     # Relying Party (OIDC Client + SSF Push Receiver)
│   ├── cmd/                # Entry point (main.go)
│   ├── internal/
│   │   ├── handler/        # HTTP handlers
│   │   ├── service/        # OIDC/Session/SSF services
│   │   └── storage/postgres/  # PostgreSQL storage + sqlc
│   ├── db/postgres/        # Schema and migrations
│   └── templates/          # HTML templates
├── rp2/                    # Relying Party 2 (OIDC Client + SSF Poll Receiver)
│   ├── cmd/                # Entry point (main.go)
│   ├── internal/           # Same structure as rp/
│   ├── db/postgres/        # Schema and migrations
│   └── templates/          # HTML templates
├── pkg/ssf/                # Shared SSF implementation
│   ├── transmitter.go      # SET transmitter
│   ├── receiver.go         # SET receiver
│   └── set.go              # Security Event Token types
├── docker/                 # Dockerfiles
│   ├── idp/Dockerfile      # IdP container
│   ├── rp/Dockerfile       # RP container
│   ├── rp2/Dockerfile      # RP2 container
│   ├── migration/Dockerfile # DB migration job
│   └── postgres/           # PostgreSQL init scripts
└── go.mod                  # Single module for the monorepo
```

### IdP - Identity Provider (Port 8080)
Built on **ory/fosite** framework, implementing OAuth 2.0, OpenID Connect, and SSF Transmitter.

- `idp/internal/provider/` - Core OIDC provider with fosite, RSA JWT signing, PKCE
- `idp/internal/handler/` - OIDC endpoints (authorize, token, userinfo, jwks, discovery) + SSF API
- `idp/internal/portal/` - Admin portal (user/client/SSF stream management)
- `idp/internal/storage/postgres/` - Fosite storage interface + sqlc generated code

### RP - Relying Party (Port 8081) - Push Delivery
OIDC Client with SSF Push Receiver (IdP pushes events to RP endpoint).

- `rp/internal/handler/` - OIDC flow + SSF receiver endpoint
- `rp/internal/service/` - OIDC protocol, session management, SSF client

### RP2 - Relying Party 2 (Port 8082) - Poll Delivery
OIDC Client with SSF Poll Receiver (RP2 polls IdP for events).

- `rp2/internal/` - Same structure as RP, but uses poll-based SSF delivery

### Shared Packages

- `pkg/ssf/` - SSF (Shared Signals Framework) core
  - `transmitter.go` - Event transmitter with retry logic
  - `receiver.go` - Event receiver with signature verification
  - `set.go` - Security Event Token (SET) definitions

## SSF Event Types

Supported RISC/CAEP event types:
- `session-revoked` - Session invalidation
- `token-claims-change` - Token claims updated
- `credential-change` - Credential changed
- `account-purged` - Account deleted
- `account-disabled` - Account suspended
- `account-enabled` - Account re-enabled

## Important Implementation Details

### Security Features
- Client secrets hashed with bcrypt
- HTTPOnly cookies for sessions
- CSRF protection via state parameter
- PKCE support for public clients
- RSA-signed SETs for integrity

### Token Configuration
- Access tokens: 1 hour
- Refresh tokens: 30 days
- Authorization codes: 10 minutes
- ID tokens: standard OIDC claims

### Initial Setup
On first run, the system requires setup of the owner account:
1. Access any page → redirected to `/setup`
2. Create owner account (username, email, password)
3. Owner is the highest privilege user (cannot be deleted or role-changed)

### User Roles
| Role | Description |
|------|-------------|
| `owner` | Highest privilege. One per system. Cannot be modified. |
| `admin` | Administrator. Can manage users and clients. |
| `user` | Regular user. |

### Default Test Clients
- **RP (Push)**: Client ID `test-client`, Secret `test-secret`, Redirect `http://localhost:8081/callback`
- **RP2 (Poll)**: Client ID `test-client2`, Secret `test-secret2`, Redirect `http://localhost:8082/callback`

### Portal
- URL: `http://localhost:8080/portal`
- Admin features (user/client/SSF management) visible for admin/owner roles only
