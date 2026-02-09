# Okta Setup

## 1. Create Application

1. Okta Admin: `Applications > Create App Integration`.
2. Choose `OIDC - Web Application` (recommended) or SAML 2.0.
3. Configure sign-in redirect URI:
   - `https://<your-host>/auth/oidc/callback`

## 2. OIDC Environment Variables

- `TW_OIDC_ISSUER=https://<okta-domain>/oauth2/default`
- `TW_OIDC_CLIENT_ID=<okta-client-id>`
- `TW_OIDC_CLIENT_SECRET=<okta-client-secret>`
- `TW_OIDC_REDIRECT_URI=https://<your-host>/auth/oidc/callback`
- `TW_OIDC_SCOPES=openid,profile,email,groups`
- `TW_OIDC_REQUIRE_MFA=true`

## 3. Group to Role Mapping

Example:

- `TW_SSO_ROLE_MAPPING=okta-soc-admin=admin,okta-soc-analyst=analyst,okta-soc-viewer=viewer`

## 4. Optional SCIM Provisioning

SCIM can be enabled on top of JIT provisioning for pre-provisioning and automated lifecycle.
JIT remains active for first-login provisioning fallback.

