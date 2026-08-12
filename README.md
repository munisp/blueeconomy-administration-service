# Blue Economy Central Administration Service

This Go service provides the approval-controlled backend for Ministry user and stakeholder onboarding. It stores **onboarding requests and decisions only** in PostgreSQL; it does not operate a local user directory, password store, token store or credential issuer. Keycloak is the authoritative identity system.

## API-edge identity boundary

The service is intended to run behind the approved API edge. The API edge must validate OIDC tokens, enforce route roles and inject `X-Blueeconomy-Authenticated-Subject` only after successful authentication. The service must not be internet-accessible directly, because it trusts this protected upstream identity assertion. Mutual network identity and API-edge route policy are mandatory deployment controls.

| Method and path | Required upstream role | Function |
|---|---|---|
| `POST /v1/onboarding/requests` | `stakeholder.onboarding.request` | Record a request for an approved organization and allowed roles. |
| `POST /v1/onboarding/requests/{id}/decision` | `stakeholder.onboarding.approve` | Approve or reject a request; self-approval is rejected. |
| `POST /v1/onboarding/requests/{id}/provision` | Dedicated provisioning approval policy | Claim one approved request and call the documented Keycloak organization invitation endpoint. |
| `POST /v1/onboarding/requests/{id}/activate` | Dedicated activation approval policy | After invitation/registration, atomically activate the request and assign only the approved Keycloak organization groups for its role set. |
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
| `KEYCLOAK_ROLE_GROUP_MAPPING_JSON` | Non-secret JSON map from each approved role to its actual approved Keycloak organization group ID. |

The Keycloak client uses client credentials and invokes the documented organization `invite-user` administrative operation after an atomic PostgreSQL claim. After an authorised invitation/registration result is available, the activation endpoint maps the request’s approved roles to the configured Keycloak organization groups using the documented organization group-membership operation. It sends no account password, raw OIDC user token, refresh token or secret to the database or its HTTP response.

## Integration gate

The source has passed deterministic local policy tests. A real release still requires a Ministry-controlled PostgreSQL target, Keycloak realm/service account/organization, APISIX route policy, distinct requester and approver test identities, approved outbound invitation path, role catalogue, audit/logging pipeline and security review. The acceptance test must demonstrate request, maker/checker denial, approval, Keycloak invitation, failure handling, role denial and evidence retention against that authorised environment.
