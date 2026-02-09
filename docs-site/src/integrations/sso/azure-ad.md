# Azure AD (Microsoft Entra ID) Setup

## 1. Register App

1. Microsoft Entra admin center: `Applications > App registrations > New registration`.
2. Add redirect URI:
   - OIDC: `https://<your-host>/auth/oidc/callback`
   - SAML ACS (if using SAML): `https://<your-host>/auth/saml/acs`
3. Save `Application (client) ID` and `Directory (tenant) ID`.

## 2. Configure OIDC in Triage Warden

Set:

- `TW_OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0`
- `TW_OIDC_CLIENT_ID=<application-client-id>`
- `TW_OIDC_CLIENT_SECRET=<generated-client-secret>`
- `TW_OIDC_REDIRECT_URI=https://<your-host>/auth/oidc/callback`
- `TW_OIDC_SCOPES=openid,profile,email`
- `TW_OIDC_REQUIRE_MFA=true` (recommended)

## 3. Claims and Group Mapping

1. In app `Token configuration`, add group claims.
2. Map groups to roles:
   - `TW_SSO_ROLE_MAPPING=SOC-Admins=admin,SOC-Analysts=analyst,SOC-Viewers=viewer`

## 4. Conditional Access / MFA

1. Create conditional access policy requiring MFA for the app.
2. Keep `TW_OIDC_REQUIRE_MFA=true` to enforce server-side claim checks.

