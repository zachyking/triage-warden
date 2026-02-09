# Stage 6 Security Status

This document tracks implemented Stage 6 security and compliance capabilities in the API/core layers.

## Authentication (6.1)

### OIDC

Implemented:
- Authorization Code + PKCE login flow (`/auth/oidc/login`, `/auth/oidc/callback`).
- Session-backed logout (`/auth/oidc/logout`) and refresh (`/auth/oidc/refresh`).
- Signature verification for `id_token` using JWKS from discovery or `TW_OIDC_JWKS_URI`.
- Claim validation: issuer, audience, nonce, expiration.
- JIT provisioning + optional MFA enforcement (`TW_OIDC_REQUIRE_MFA`).

### SAML

Implemented:
- SP metadata/login/ACS/SLO endpoints (`/auth/saml/*`).
- Assertion validation for audience, issuer (optional configured), validity window, signature presence, certificate pinning.
- Request/response correlation via `InResponseTo` against stored AuthnRequest ID.
- Destination/recipient validation against configured ACS URL.
- RelayState validation and open-redirect protection.
- Signature/digest algorithm allow-listing (SHA-2 based).

## RBAC (6.2)

Implemented:
- Permission/resource/action model.
- Built-in enterprise role catalog.
- SoD rules + enforcement/warn/audit behavior on assignment.
- Access review campaign model and API workflow.
- Reminder and attestation decision recording with optional role revocation application.
- Route-level RBAC middleware enforced on Stage 6 APIs:
  - `/api(/v1)/roles` -> `role:manage`
  - `/api(/v1)/audit` -> `audit_log:read`
  - `/api(/v1)/compliance` -> `compliance:read`
  - `/api(/v1)/privacy` -> `privacy:read`
  - `/api(/v1)/guardrails` -> `guardrail:read`

## AI Privacy (6.3)

Implemented:
- Sensitive data classification and masking policies.
- Retention policy API with evaluation.
- Retention cleanup planning API:
  - `POST /api(/v1)/privacy/retention/cleanup/plan`
- Subject access and right-to-deletion workflow tracking:
  - `GET /api(/v1)/privacy/subject-access/requests`
  - `POST /api(/v1)/privacy/subject-access/export`
  - `POST /api(/v1)/privacy/subject-access/delete`
- Local/cloud routing decision API for sensitive prompts.
- Python ReAct routing support with sensitivity-aware provider selection and AI interaction audit hooks.

## Guardrails (6.4)

Implemented:
- Dry-run simulation endpoint.
- Rollback metadata registry with tenant persistence.
- Automation anomaly detection endpoint with auto-pause signal.

## Compliance and Audit (6.5)

Implemented:
- Immutable audit chain export/anchor/verify endpoints.
- Immutable archive snapshots with index and latest retrieval:
  - `POST /api(/v1)/audit/immutable/archive`
  - `GET /api(/v1)/audit/immutable/archive/index`
  - `GET /api(/v1)/audit/immutable/archive/latest`
- Compliance report generation, retrieval, listing, and checksum verification:
  - `GET /api(/v1)/compliance/reports`
  - `POST /api(/v1)/compliance/reports/generate`
  - `GET /api(/v1)/compliance/reports/:report_id`
  - `GET /api(/v1)/compliance/reports/:report_id/verify`
- Evidence package creation, retrieval, listing, integrity verification, and chain-of-custody updates:
  - `POST /api(/v1)/compliance/evidence/package`
  - `GET /api(/v1)/compliance/evidence/packages`
  - `GET /api(/v1)/compliance/evidence/package/:package_id`
  - `GET /api(/v1)/compliance/evidence/package/:package_id/verify`
  - `POST /api(/v1)/compliance/evidence/package/:package_id/custody`
- Security metrics endpoint:
  - `GET /api(/v1)/compliance/metrics`

## Remaining Work (Stage 6 scope)

Items that still require broader product/system work beyond current API/core implementation:
- External immutable audit archival targets (S3/Azure Blob) and automated integrity-alert jobs.
- End-to-end UI for roles/access-review/privacy/guardrails/compliance dashboards.
- Full endpoint-by-endpoint RBAC annotations across all routes.
- Full cryptographic SAML XML signature verification (XMLDSIG canonicalization/verification library integration).
- Scheduled retention cleanup executors and DSAR deletion orchestration jobs.
