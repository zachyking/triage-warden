# Generic OIDC/SAML Setup

## OIDC Checklist

1. Configure redirect URI: `https://<host>/auth/oidc/callback`.
2. Set:
   - `TW_OIDC_ISSUER`
   - `TW_OIDC_CLIENT_ID`
   - `TW_OIDC_CLIENT_SECRET`
   - `TW_OIDC_REDIRECT_URI`
3. Optional claim overrides:
   - `TW_OIDC_EMAIL_CLAIM`
   - `TW_OIDC_NAME_CLAIM`
   - `TW_OIDC_GROUPS_CLAIM`
   - `TW_OIDC_ROLES_CLAIM`
   - `TW_OIDC_MFA_CLAIM`
4. Configure role mapping:
   - `TW_SSO_ROLE_MAPPING=external_group=internal_role,...`

## SAML Checklist

1. Download SP metadata from `https://<host>/auth/saml/metadata`.
2. Configure IdP to POST assertions to `https://<host>/auth/saml/acs`.
3. Set:
   - `TW_SAML_ENTITY_ID`
   - `TW_SAML_ACS_URL`
   - `TW_SAML_IDP_SSO_URL`
   - `TW_SAML_CERTIFICATE`
4. Optional:
   - `TW_SAML_PRIVATE_KEY` (required for encrypted assertions)
   - `TW_SAML_IDP_SLO_URL`
   - `TW_SAML_EXPECTED_ISSUER`
   - `TW_SAML_REQUIRE_MFA`

## Security Recommendations

- Always require TLS termination.
- Keep `TW_OIDC_REQUIRE_MFA=true` and `TW_SAML_REQUIRE_MFA=true` for privileged tenants.
- Use least-privilege role mappings.
- Rotate OIDC client secrets and SAML certificates regularly.

