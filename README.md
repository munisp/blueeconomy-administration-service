# Blue Economy Central Administration Service

This Go service provides the approval-controlled backend for Ministry user and stakeholder onboarding. It stores **onboarding requests and decisions only** in PostgreSQL; it does not operate a local user directory, password store, token store or credential issuer. Keycloak is the authoritative identity system.

## API-edge identity boundary

The service is intended to run behind the approved API edge. Mutual network identity and API-edge route policy remain mandatory deployment controls, but the service **enforces its own service-side authorization** and never relies on the edge alone.

In `jwt` mode the service validates RS256 bearer tokens against the configured JWKS and reads roles from the token claims. In `trusted_proxy` mode the approved API edge must validate OIDC tokens and inject `X-Blueeconomy-Authenticated-Subject` **and** `X-Blueeconomy-Authenticated-Roles` (comma-separated) only after successful authentication; the service verifies the trusted proxy source and identity header before accepting either assertion. The service must not be internet-accessible directly in `trusted_proxy` mode.

### Role claim mapping

Roles are Keycloak realm roles. In `jwt` mode they are read from the token's `realm_access.roles` claim and, additionally, from `resource_access[<client>].roles` for each client ID listed in `ADMIN_OIDC_ROLES_CLIENT_IDS`. Roles of any other client are ignored. A token with no role claim is authenticated but denied (403) on every protected route.

Approved realm roles: `platform-admin`, `nimasa-officer`, `nwa-officer`, `niwa-officer`, `cbn-observer`, `fmmbe-oversight`, `independent-auditor`, `icrc-observer`.

Authorization is fail-closed and default-deny: any route not in the policy table receives 403, and the read-only oversight roles (`cbn-observer`, `fmmbe-oversight`, `independent-auditor`, `icrc-observer`) are generically denied every mutating endpoint regardless of the route table.

| Method and path | Allowed roles | Function |
|---|---|---|
| `POST /v1/onboarding/requests` | `platform-admin`, `nimasa-officer`, `nwa-officer`, `niwa-officer` | Record a request for an approved organization and allowed roles. |
| `POST /v1/onboarding/requests/{id}/decision` | `platform-admin`, `nimasa-officer` | Approve or reject a request; self-approval is rejected. |
| `POST /v1/onboarding/requests/{id}/provision` | `platform-admin`, `nimasa-officer` | Claim one approved request and call the documented Keycloak organization invitation endpoint. |
| `POST /v1/onboarding/requests/{id}/activate` | `platform-admin`, `nimasa-officer` | After invitation/registration, atomically activate the request and assign only the approved Keycloak organization groups for its role set. |
| `POST /v1/privacy/activities` | `platform-admin`, `nimasa-officer`, `nwa-officer`, `niwa-officer` | Record a privacy processing activity in draft. |
| `GET /v1/privacy/activities/{id}` | All eight approved roles | Read one privacy processing activity (the only route open to oversight roles). |
| `POST /v1/privacy/activities/{id}/attest` | `platform-admin`, `nimasa-officer`, `nwa-officer`, `niwa-officer` | Recorded owner attests the draft activity. |
| `POST /v1/privacy/activities/{id}/submit-dpo-review` | `platform-admin`, `nimasa-officer`, `nwa-officer`, `niwa-officer` | Recorded owner submits the attested activity for DPO review. |
| `POST /v1/privacy/activities/{id}/decision` | `platform-admin`, `nimasa-officer` | Independent DPO decision; requester/owner self-decision is rejected. |
| `GET /healthz` | Network-restricted operational probe | Report process health only. |

## Required configuration

All configuration must be supplied by the approved deployment/secret mechanism. The service fails if any mandatory value is missing:

| Variable | Purpose |
|---|---|
| `ADMIN_SERVICE_LISTEN_ADDRESS` | Internal listener, exposed only by the API edge. |
| `ADMIN_SERVICE_POSTGRES_DSN` | Approved PostgreSQL DSN for request and decision evidence. |
| `KEYCLOAK_TOKEN_URL` | Actual HTTPS token endpoint for the dedicated provisioning service account. |
| `KEYCLOAK_ADMIN_BASE_URL` | Actual HTTPS Keycloak base URL used for Administrative REST calls. |
| `KEYCLOAK_REALM` and `KEYCLOAK_ORGANIZATION_ID` | Approved target realm and stakeholder organization. |
| `KEYCLOAK_ADMIN_CLIENT_ID` and `KEYCLOAK_ADMIN_CLIENT_SECRET` | Dedicated least-privilege confidential client credentials. |
| `KEYCLOAK_SERVICE_ACTOR_SUBJECT` | Immutable non-human actor reference recorded for provisioning results. |
| `ONBOARDING_ALLOWED_ROLES` | Comma-separated approved service-role catalogue. |
| `ADMIN_OIDC_ROLES_CLIENT_IDS` | Optional comma-separated Keycloak client IDs whose `resource_access` roles are trusted in `jwt` mode, in addition to `realm_access.roles`. |
| `KEYCLOAK_ROLE_GROUP_MAPPING_JSON` | Non-secret JSON map from each approved role to its actual approved Keycloak organization group ID. |

The Keycloak client uses client credentials and invokes the documented organization `invite-user` administrative operation after an atomic PostgreSQL claim. After an authorised invitation/registration result is available, the activation endpoint maps the request’s approved roles to the configured Keycloak organization groups using the documented organization group-membership operation. It sends no account password, raw OIDC user token, refresh token or secret to the database or its HTTP response.

## Integration gate

The source has passed deterministic local policy tests. A real release still requires a Ministry-controlled PostgreSQL target, Keycloak realm/service account/organization, APISIX route policy, distinct requester and approver test identities, approved outbound invitation path, role catalogue, audit/logging pipeline and security review. The acceptance test must demonstrate request, maker/checker denial, approval, Keycloak invitation, failure handling, role denial and evidence retention against that authorised environment.
