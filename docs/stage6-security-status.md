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
- Cryptographic XMLDSIG signature verification integrated in ACS (canonicalization + digest/signature verification).
- ACS claim extraction now consumes signed XML reference content returned by XMLDSIG verification (not raw response XML).
- Assertion validation for audience, issuer (optional configured), validity window, and certificate pinning.
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
- RBAC middleware enforced across API route groups (except intentionally public auth/webhook/health/metrics routes), including:
  - `/api(/v1)/roles` -> `role:manage`
  - `/api(/v1)/audit` -> `audit_log:read`
  - `/api(/v1)/compliance` -> `compliance:read`
  - `/api(/v1)/privacy` -> `privacy:read`
  - `/api(/v1)/guardrails` -> `guardrail:read`
  - `/api(/v1)/kill-switch` -> `guardrail:read` (activate/deactivate still enforce `guardrail:manage` in handler)
  - `/api(/v1)/connectors` -> `connector:read`
  - `/api(/v1)/settings` -> `settings:read`
  - `/api(/v1)/api-keys` -> `api_key:manage`
  - Incident-adjacent groups (`feedback`, `comments`, `activity`, `handoffs`, `assets`, `identities`, `iocs`, `lessons`) -> `incident:read`
- Endpoint-level action resolution for protected routes:
  - Default behavior for read-protected groups: `GET/HEAD/OPTIONS -> read`, mutating methods -> `update`.
  - Explicit endpoint overrides for `execute`/`approve`/`export`/`manage` where applicable (e.g. incident action execution/approval, immutable audit export/anchor/archive, DSAR export/delete).
- API-key scope enforcement in middleware:
  - Scope gating tracks resolved RBAC action (`read` action requires `read`; all stronger actions require `write`).
  - Resource scopes enforced where applicable (`incidents`, `connectors`, `playbooks`, `settings`, `admin`).

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
- Scheduled retention cleanup executor with DSAR plan progression + audit-retention action application.
- DSAR plans that cannot be auto-executed by backend handlers are retained as `pending_manual_review` (not auto-marked `completed`).
- DSAR deletion plan statuses are strongly typed (`scheduled`, `pending_manual_review`, `completed`) and persisted as stable enums.
- DSAR scheduler counters are now accurate for both `dsar_plans_completed` and `dsar_pending_manual_review`.
- DSAR requests are only auto-completed when plan list is non-empty and every plan is `completed`.
- DSAR deletion request planning deduplicates repeated data types and marks missing-policy data types as `pending_manual_review` with explicit reason.
- Local/cloud routing decision API for sensitive prompts.
- Python ReAct routing support with sensitivity-aware provider selection and AI interaction audit hooks.

## Guardrails (6.4)

Implemented:
- Dry-run simulation endpoint.
- Rollback metadata registry with tenant persistence.
- Rollback derivation for common reversible actions:
  - `POST /api(/v1)/guardrails/rollback/derive`
- Automation anomaly detection endpoint with auto-pause signal.
- Persisted automation pause state and resume endpoints:
  - `GET /api(/v1)/guardrails/automation/pause`
  - `POST /api(/v1)/guardrails/automation/pause/resume`
- Auto-pause enforcement in simulation path (`/api(/v1)/guardrails/simulate`) with pause expiry handling.

## Compliance and Audit (6.5)

Implemented:
- Immutable audit chain export/anchor/verify endpoints.
- Immutable verification job with persisted integrity alerts:
  - `POST /api(/v1)/audit/immutable/verify/job`
  - `GET /api(/v1)/audit/immutable/verify/alerts`
- Scheduled immutable verification orchestration with tenant-scoped persisted scheduler status.
- Scheduled Stage 6 jobs use PostgreSQL advisory-lock coordination to avoid duplicate execution across API instances.
- Immutable archive snapshots with index and latest retrieval:
  - `POST /api(/v1)/audit/immutable/archive`
  - `GET /api(/v1)/audit/immutable/archive/index`
  - `GET /api(/v1)/audit/immutable/archive/latest`
  - External archival targets:
    - Filesystem (`TW_IMMUTABLE_ARCHIVE_DIR` / `TW_IMMUTABLE_ARCHIVE_TARGET=filesystem`)
    - S3 (`TW_IMMUTABLE_ARCHIVE_TARGET=s3` + S3 credentials/bucket envs)
    - Azure Blob (`TW_IMMUTABLE_ARCHIVE_TARGET=azure_blob` + Azure account/container/key envs)
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
- Security hardening items tracked outside Stage 6 implementation scope.
