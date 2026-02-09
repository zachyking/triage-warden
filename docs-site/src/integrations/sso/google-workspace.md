# Google Workspace Setup

## 1. Configure OAuth Consent and Client

1. Google Cloud Console: configure OAuth consent screen.
2. Create OAuth client (Web application).
3. Add authorized redirect URI:
   - `https://<your-host>/auth/oidc/callback`

## 2. OIDC Configuration

- `TW_OIDC_ISSUER=https://accounts.google.com`
- `TW_OIDC_CLIENT_ID=<google-client-id>`
- `TW_OIDC_CLIENT_SECRET=<google-client-secret>`
- `TW_OIDC_REDIRECT_URI=https://<your-host>/auth/oidc/callback`
- `TW_OIDC_SCOPES=openid,profile,email`

## 3. Role Mapping

Google Workspace group claims may require Cloud Identity configuration.
Use mapped group names:

- `TW_SSO_ROLE_MAPPING=tw-admins=admin,tw-analysts=analyst,tw-viewers=viewer`

## 4. MFA

Enforce 2-Step Verification in Workspace admin policies and set:

- `TW_OIDC_REQUIRE_MFA=true`

