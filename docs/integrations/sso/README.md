# SSO Integration Guide

Triage Warden supports enterprise SSO through both OIDC and SAML endpoints.

## Supported Flows

- OIDC login: `/auth/oidc/login`
- OIDC callback: `/auth/oidc/callback`
- OIDC logout: `/auth/oidc/logout`
- SAML metadata: `/auth/saml/metadata`
- SAML login: `/auth/saml/login`
- SAML ACS: `/auth/saml/acs`
- SAML SLO: `/auth/saml/slo`

## Common Environment Variables

- `TW_OIDC_ISSUER`
- `TW_OIDC_CLIENT_ID`
- `TW_OIDC_CLIENT_SECRET`
- `TW_OIDC_REDIRECT_URI`
- `TW_OIDC_SCOPES`
- `TW_OIDC_JWKS_URI` (optional override; discovery `jwks_uri` is used by default)
- `TW_OIDC_REQUIRE_MFA`
- `TW_SSO_ROLE_MAPPING`
- `TW_SSO_DEFAULT_ROLE`
- `TW_SSO_AUTO_CREATE_USERS`
- `TW_SAML_ENTITY_ID`
- `TW_SAML_ACS_URL`
- `TW_SAML_IDP_SSO_URL`
- `TW_SAML_CERTIFICATE`
- `TW_SAML_PRIVATE_KEY`
- `TW_SAML_EXPECTED_ISSUER`
- `TW_SAML_REQUIRE_MFA`

Use provider-specific documents in this folder for exact values.

## Security Notes

- OIDC ID tokens are validated for issuer/audience/nonce/expiration and signature (JWKS).
- SAML assertions enforce signature presence and certificate pinning checks.
