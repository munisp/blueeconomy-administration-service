# Blue Economy Central Administration Service

This Go service provides the approval-controlled backend for Ministry user and stakeholder onboarding. It stores **onboarding requests and decisions only** in PostgreSQL; it does not operate a local user directory, password store, token store or credential issuer. Keycloak is the authoritative identity system.

## API-edge identity boundary

The service is intended to run behind the approved API edge. The API edge must validate OIDC tokens, enforce route roles and inject `X-Blueeconomy-Authenticated-Subject` plus the caller's realm roles in `X-Blueeconomy-Authenticated-Roles` (comma-separated lower-case slugs) only after successful authentication. The service must not be internet-accessible directly, because it trusts this protected upstream identity assertion. Mutual network identity and API-edge route policy are mandatory deployment controls.

Authorization is additionally enforced inside the service (defense in depth, phase-20 GAP-2 fix): `submit` is open to any authenticated principal, while `decide`, `provision` and `activate` require the configured approver role (`ADMIN_ONBOARDING_APPROVER_ROLE`, default `onboarding-approver`) asserted via the roles header (trusted_proxy mode) or the verified JWT `realm_access.roles` / approved `resource_access` client roles (jwt mode). The maker/checker rule is enforced in the store: the decider subject must differ from the requester subject. Every decision, provisioning result and activation result is recorded in `onboarding_decisions` bound to the acting principal's verified subject.

| Method and path | Required role (edge and in-service) | Function |
|---|---|---|
| `POST /v1/onboarding/requests` | any authenticated principal | Record a request for an approved organization and allowed roles. |
| `POST /v1/onboarding/requests/{id}/decision` | `onboarding-approver` | Approve or reject a request; self-approval (maker = checker) is rejected. |
| `POST /v1/onboarding/requests/{id}/provision` | `onboarding-approver` | Claim one approved request and call the documented Keycloak organization invitation endpoint. |
| `POST /v1/onboarding/requests/{id}/activate` | `onboarding-approver` | After invitation/registration, atomically activate the request and assign only the approved Keycloak organization groups for its role set. |
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
| `ADMIN_ONBOARDING_APPROVER_ROLE` | Realm role gating decide/provision/activate; defaults to `onboarding-approver`. Must be a lower-case slug. |
| `ADMIN_OIDC_ROLES_CLIENT_IDS` | jwt mode only: optional comma-separated additional client IDs whose `resource_access` roles are honoured in addition to `realm_access.roles`. |
| `KEYCLOAK_ROLE_GROUP_MAPPING_JSON` | Non-secret JSON map from each approved role to its actual approved Keycloak organization group ID. |

The Keycloak client uses client credentials and invokes the documented organization `invite-user` administrative operation after an atomic PostgreSQL claim. After an authorised invitation/registration result is available, the activation endpoint maps the request’s approved roles to the configured Keycloak organization groups using the documented organization group-membership operation. It sends no account password, raw OIDC user token, refresh token or secret to the database or its HTTP response.

## Integration gate

The source has passed deterministic local policy tests. A real release still requires a Ministry-controlled PostgreSQL target, Keycloak realm/service account/organization, APISIX route policy, distinct requester and approver test identities, approved outbound invitation path, role catalogue, audit/logging pipeline and security review. The acceptance test must demonstrate request, maker/checker denial, approval, Keycloak invitation, failure handling, role denial and evidence retention against that authorised environment.
