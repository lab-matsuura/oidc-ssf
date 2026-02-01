# SSF (Shared Signals Framework) Research Implementation

This repository is a research implementation of a real-time security event delivery infrastructure using the Shared Signals Framework (SSF) standardized by the OpenID Foundation. It provides a complete verification environment including an OIDC Provider and Client, with interoperability evaluation through SSF Conformance Tests and performance measurements.

## Research Overview

### Background and Objectives

Current identity federation has structural challenges. In existing protocols such as OpenID Connect, the coordination between IdP and RP is limited to **authentication time only**. After authentication is complete, even if a security issue occurs on the IdP side (logout, account deactivation, etc.), there is no mechanism to notify the RP. As a result, sessions for users invalidated at the IdP continue to persist on the RP side.

This research implements SSF specification-compliant Transmitter/Receiver to verify the following:

1. **Interoperability**: Specification compliance verification through the OpenID SSF Conformance Test Suite
2. **Use Case Demonstration**: Immediate propagation of single logout, token claim changes, and account deactivation
3. **Performance Evaluation**: Latency and throughput measurement of Push/Poll delivery

### Key Implementation Features

#### SSF Transmitter (IdP Side)
- Real-time event notification via Push-based delivery (RFC 8935)
- Poll-based delivery support (RFC 8936)
- RISC/CAEP event type support
- Retry mechanism with exponential backoff
- Authentication via Client Credentials Grant (RFC 6749)

#### SSF Receiver (RP Side - Push Delivery)
- Signature verification with automatic JWKS retrieval and caching
- JTI duplicate detection (replay attack prevention)
- Flexible processing through event handlers
- Automatic session invalidation

#### SSF Receiver (RP2 Side - Poll Delivery)
- Poll-based SET retrieval (RFC 8936)
- Periodic polling for event retrieval
- Reliable event processing through ACK management
- Event handling equivalent to Push delivery

#### OIDC Infrastructure
- OIDC Provider based on ory/fosite
- Authorization code flow + PKCE
- Admin console (user and client management)

### System Screenshots

For a visual overview of all system screens including the IdP Portal, RP, and RP2 interfaces, see [SYSTEM.md](SYSTEM.md).

## Repository Structure

```
ssf/
├── idp/                        # Identity Provider (OIDC Provider + SSF Transmitter)
│   ├── cmd/main.go             # Entry point
│   ├── internal/
│   │   ├── handler/            # HTTP handlers
│   │   │   ├── authorize.go    # Authorization endpoint
│   │   │   ├── token.go        # Token endpoint
│   │   │   ├── ssf_api.go      # SSF Transmitter API (RFC 8935/8936)
│   │   │   └── ...
│   │   ├── portal/handler/     # Portal (admin console)
│   │   ├── middleware/         # Middleware (setup check, etc.)
│   │   ├── provider/           # OIDC Provider implementation (ory/fosite)
│   │   ├── user/               # User service
│   │   └── storage/postgres/   # PostgreSQL storage (sqlc)
│   ├── db/postgres/            # DB schema and migrations
│   └── templates/              # HTML templates
│
├── rp/                         # Relying Party (OIDC Client + SSF Receiver - Push Delivery)
│   ├── cmd/main.go             # Entry point
│   ├── internal/
│   │   ├── config/             # Configuration
│   │   ├── handler/
│   │   │   ├── ssf.go          # SSF Receiver API (Push reception)
│   │   │   └── ...
│   │   ├── service/            # OIDC/Session/PKCE/SSF
│   │   └── storage/postgres/   # PostgreSQL storage (sqlc)
│   ├── db/postgres/            # DB schema and migrations
│   └── templates/
│
├── rp2/                        # Relying Party 2 (OIDC Client + SSF Receiver - Poll Delivery)
│   ├── cmd/main.go             # Entry point
│   ├── internal/
│   │   ├── config/             # Configuration
│   │   ├── handler/            # HTTP handlers (no SSF endpoint)
│   │   ├── service/
│   │   │   ├── ssf_client.go   # SSF Stream management
│   │   │   └── ssf_poller.go   # Poll-based SET retrieval (RFC 8936)
│   │   └── storage/postgres/   # PostgreSQL storage (sqlc)
│   ├── db/postgres/            # DB schema and migrations
│   └── templates/
│
├── pkg/ssf/                    # Shared SSF implementation (core of the research)
│   ├── transmitter.go          # SET transmission (Push/Poll delivery)
│   ├── receiver.go             # SET reception and signature verification
│   └── set.go                  # Security Event Token definitions
│
├── docs/                       # Documentation
│   ├── architecture/           # Architecture documentation
│   ├── openid-certificate/     # SSF Conformance Test logs
│   │   ├── ssf-transmitter-push-based-test-logs/  # Push delivery test results
│   │   └── ssf-transmitter-poll-based-test-logs/  # Poll delivery test results
│   ├── research/               # Research papers (LaTeX)
│   └── tasks/                  # Development task specifications
│
├── benchmark/                  # Performance evaluation tools
│   ├── cmd/
│   │   ├── driver/             # Benchmark driver
│   │   └── receiver/           # Mock SET receiver
│   ├── internal/
│   │   ├── driver/             # Setup, emission, analysis
│   │   └── receiver/           # Push reception handler
│   └── docker-compose.yml      # Docker environment
│
├── docker/                     # Dockerfiles
│   ├── idp/                    # IdP container
│   ├── rp/                     # RP container
│   ├── rp2/                    # RP2 container
│   ├── migration/              # DB migration job
│   └── postgres/               # PostgreSQL initialization scripts
│
├── terraform/dev/gcp/          # GCP infrastructure (Terraform)
├── scripts/                    # Utility scripts
│   └── db-tunnel.sh            # Cloud SQL connection tunnel
├── .github/workflows/          # GitHub Actions
├── Makefile                    # Build and run commands
├── compose.yaml                # PostgreSQL (development environment)
├── atlas.hcl                   # Atlas migration configuration
└── sqlc.yaml                   # sqlc code generation configuration
```

## Evaluation Environment

### Evaluation Items

1. **Interoperability Evaluation**: [SSF Conformance Test Suite](https://openid.net/certification/ssf_testing/)
2. **Performance Evaluation**: Latency and scalability measurement

See [docs/openid-certificate/README.md](docs/openid-certificate/README.md) for details.

### SSF Conformance Test Results

Executed the OpenID Foundation's SSF Transmitter Conformance Test Suite and achieved **all tests passed**.

| Delivery Method | Test Count | Result |
|-----------------|------------|--------|
| Push (RFC 8935) | 18 | All PASSED |
| Poll (RFC 8936) | 17 | All PASSED |

Test logs are saved in the [docs/openid-certificate/](docs/openid-certificate/) directory. See [docs/openid-certificate/README.md](docs/openid-certificate/README.md) for details.

### Performance Evaluation

A benchmark infrastructure has been implemented to evaluate SSF scalability.

#### Measurement Items

| Metric | Description |
|--------|-------------|
| **Throughput** | SETs/sec (event delivery rate) |
| **Latency** | P50/P95/P99 (time from SET issuance to reception) |
| **Duplicate Rate** | Number of duplicate receptions with the same JTI |

See [benchmark/README.md](benchmark/README.md) for details.

## Quick Start

### Requirements
- Go 1.25 or later
- Docker / Docker Compose

### Setup and Launch

```bash
# 1. Install dependencies
go mod tidy

# 2. Start PostgreSQL
docker compose up -d

# 3. Run database migrations
make db-migrate-apply

# 4. Start all servers simultaneously
make run

# 5. Access the following URL in your browser
# http://localhost:8081
```

### Build

```bash
make build
```

### Database Commands

```bash
# Start PostgreSQL
docker compose up -d

# Apply migrations
make db-migrate-apply

# Generate migrations from schema changes
make db-migrate

# Regenerate Go code with SQLC
make sqlc-gen

# Complete setup (migrate + generate)
make db-setup
```

### Benchmarks

```bash
# Build
make bench-build

# Push delivery benchmark
make bench-receiver       # Start Mock Receiver (terminal 1)
make bench-setup RPS=5 USERS=100 MODE=push  # Setup
make bench-emit CONCURRENCY=10              # Emit events
make bench-analyze                          # Analyze results

# Poll delivery benchmark
make bench-setup RPS=5 USERS=100 MODE=poll  # Setup
make bench-poll POLL_TIMEOUT=120s           # Start polling (terminal 1)
make bench-emit CONCURRENCY=10              # Emit events (terminal 2)

# Cleanup
make bench-clean
```

## Endpoints

### IdP - OIDC Provider / SSF Transmitter (localhost:8080)

#### OIDC Endpoints
| Endpoint | Description |
|----------|-------------|
| `/.well-known/openid-configuration` | OpenID Connect Discovery |
| `/authorize` | Authorization endpoint |
| `/token` | Token endpoint |
| `/userinfo` | UserInfo endpoint |
| `/jwks` | JSON Web Key Set |
| `/login`, `/logout` | Login/Logout |
| `/register` | User registration |
| `/setup` | Initial setup (Owner creation) |

#### SSF Transmitter API (RFC 8935/8936)
| Endpoint | Description |
|----------|-------------|
| `/.well-known/ssf-configuration` | SSF Configuration Metadata |
| `/ssf/stream` | Stream management (CRUD) |
| `/ssf/status` | Stream status |
| `/ssf/subjects:add`, `/ssf/subjects:remove` | Subject management |
| `/ssf/verify` | Verification event transmission |
| `/ssf/poll/{stream_id}` | Poll endpoint (RFC 8936) |

#### Portal (Admin UI)
| Endpoint | Description |
|----------|-------------|
| `/portal` | Dashboard |
| `/portal/profile` | Profile settings |
| `/portal/admin/clients` | OAuth client management (admin) |
| `/portal/admin/users` | User management (admin) |
| `/portal/admin/ssf` | SSF stream management (admin) |

### RP - OIDC Client + Push SSF (localhost:8081)

| Endpoint | Description |
|----------|-------------|
| `/` | Homepage |
| `/login` | Start OIDC authentication |
| `/callback` | Authorization code callback |
| `/profile` | Profile |
| `/logout` | Logout |
| `/ssf/receiver` | SET reception (Push delivery) |

### RP2 - OIDC Client + Poll SSF (localhost:8082)

| Endpoint | Description |
|----------|-------------|
| `/` | Homepage |
| `/login` | Start OIDC authentication |
| `/callback` | Authorization code callback |
| `/profile` | Profile |
| `/logout` | Logout |

> **Note:** RP2 uses Poll-based delivery, so there is no SSF reception endpoint. A background Poller periodically retrieves SETs from the Transmitter.

## Test Configuration

The following test clients are configured by default:

- **Client ID**: `test-client`
- **Client Secret**: `test-secret`
- **Redirect URI**: `http://localhost:8081/callback`
- **Supported Scopes**: `openid`, `profile`, `email`

## Usage

### Basic Flow

1. Start PostgreSQL: `docker compose up -d`
2. Apply migrations: `make db-migrate-apply`
3. Start servers: `make run`
4. Access `http://localhost:8081` in your browser
5. Click the "Login with OIDC" button
6. On first access, create an Owner account at `/setup` on the IdP
7. After login, you will be automatically redirected back to the RP with user information displayed
8. Use management features in the IdP Portal (`http://localhost:8080/portal`)

## Notes

- **This repository is a research-purpose implementation**
- Not intended for production use
- Aimed at verifying and evaluating SSF specifications

## Technologies Used

### Backend
- [ory/fosite](https://github.com/ory/fosite) - OAuth 2.0 / OpenID Connect framework
- [gorilla/mux](https://github.com/gorilla/mux) - HTTP routing
- [pgx](https://github.com/jackc/pgx) - PostgreSQL driver
- [sqlc](https://sqlc.dev/) - SQL to Go code generator
- [Atlas](https://atlasgo.io/) - Database schema migration
- Go standard library - Cryptography, JSON Web Token, templates

### Frontend
- HTML5 + CSS3 - Responsive Web UI
- Go html/template - Server-side rendering

### Security
- BCrypt - Client secret hashing
- HTTPOnly Cookies - Secure session management
- CSRF Protection - State parameter validation
- Base64URL - JWT token handling
- RSA signatures - Integrity guarantee for SETs (Security Event Tokens)
- Automatic session invalidation - Immediate response upon security event reception

## Related Specifications and References

### OAuth 2.0 Related RFCs
- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 6750 - The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
- [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients (PKCE)](https://tools.ietf.org/html/rfc7636)

### OpenID Connect Specifications
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)

### JWT Related Specifications
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)

### OpenID Foundation
- [OpenID Foundation Official Website](https://openid.net/)
- [Specifications List](https://openid.net/developers/specs/)

### Shared Signals Framework (SSF)
- [OpenID Shared Signals Framework Specification 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
- [RFC 8935 - Push-Based Security Event Token (SET) Delivery Using HTTP](https://tools.ietf.org/html/rfc8935)
- [RFC 8936 - Poll-Based Security Event Token (SET) Delivery Using HTTP](https://tools.ietf.org/html/rfc8936)
- [RFC 8417 - Security Event Token (SET)](https://tools.ietf.org/html/rfc8417)
- [OpenID RISC Profile Specification 1.0](https://openid.net/specs/openid-risc-1_0-final.html)
- [OpenID CAEP (Continuous Access Evaluation Profile) 1.0](https://openid.net/specs/openid-caep-1_0-final.html)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Dependencies

This project uses the following open source libraries:

| Library | License |
|---------|---------|
| [ory/fosite](https://github.com/ory/fosite) | Apache-2.0 |
| [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) | MIT |
| [jackc/pgx](https://github.com/jackc/pgx) | MIT |
| [gorilla/mux](https://github.com/gorilla/mux) | BSD-3-Clause |
| [go-jose/go-jose](https://github.com/go-jose/go-jose) | Apache-2.0 |
| [google/uuid](https://github.com/google/uuid) | BSD-3-Clause |
