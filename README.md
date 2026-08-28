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
| `POST /v1/enrollment/requests` | Public (no role), strictly rate-limited per subject/IP | Record a self-service enrollment request in `pending_verification`; it can never reach provisioning without an officer decision. |
| `POST /v1/enrollment/requests/{id}/identity-review/start` | `platform-admin`, `nimasa-officer`, `nwa-officer`, `niwa-officer` | Officer opens the KYC identity-proofing stage (`pending_verification` → `identity_review`). |
| `POST /v1/enrollment/requests/{id}/identity-review/outcome` | `platform-admin`, `nimasa-officer`, `nwa-officer`, `niwa-officer` | Officer records the identity-proofing outcome (`identity_verified`/`identity_rejected`) with document type and a sha256 digest of the document reference — never the raw number. |
| `POST /v1/enrollment/batches` | `platform-admin`, `nimasa-officer`, `nwa-officer`, `niwa-officer` | Propose an agent-assisted enrollment batch (1–500 rows); each row is validated independently and carries an explicit per-row status. |
| `POST /v1/enrollment/batches/{id}/confirm` | `platform-admin`, `nimasa-officer` | Second officer confirms the batch (proposer ≠ confirmer, database-enforced); accepted rows are enrolled with per-row failure isolation. |
| `GET /healthz` | Network-restricted operational probe | Report process health only. |

## Enrollment journeys

Self-service and agent-assisted enrollment extend the onboarding pipeline with three additional pre-decision states. The full state machine is:

```
self-service submit --> pending_verification --> identity_review --> identity_verified --+
officer submit      --> submitted -------------------------------------------------------+--> decision (approve|reject)
                                                                                          |
                        rejected <------------------------ (reject) ----------------------+
                        approved  <----------------------- (approve) ---------------------+
                            |
                            +--> provisioning --> invited --> activating --> active
                            |        |                          |
                            |        +--> provisioning_failed/  +--> activation_failed/
                            |            provisioning_ambiguous     activation_ambiguous
                            |
        identity_review --> identity_rejected (terminal; no decision or provisioning possible)
```

- **Self-service stakeholder** (personas `trucker`, `ferry-passenger`, `operator`, `fisher`, `seafarer-trainee`, `beneficiary`, `exporter`, `processor`, `fleet-operator`): submits `POST /v1/enrollment/requests` with a contact channel (`sms`, `ussd`, `email`, `app`) and reference. The endpoint is public but strictly rate-limited per subject/IP through a database-backed fixed window (`ADMIN_ENROLLMENT_RATE_LIMIT_PER_MINUTE`); a missing limit or limiter outage fails closed. The request is recorded against the non-human actor `enrollment:self-service` in `pending_verification` and is structurally unable to reach a decision — and therefore provisioning — until an officer completes identity proofing.
- **KYC identity proofing** (`nimasa-officer`, `nwa-officer`, `niwa-officer`, `platform-admin`): the officer opens review, then records the outcome with the document type and a canonical `sha256:` digest of the document reference. Raw document numbers are rejected by validation and never stored. Every transition appends an audit row (who/when/what) to the decision evidence stream, and each request admits exactly one KYC outcome.
- **Officer decision and provisioning** (`platform-admin`, `nimasa-officer`): unchanged maker/checker decision, now gated on `identity_verified` for self-service requests; provisioning and activation behave exactly as for officer-submitted requests.
- **Activation notification**: a completed activation atomically writes one platform-envelope outbox event — topic `platform.onboarding.v1`, type `onboarding.activated.v1`, classification `CONFIDENTIAL`, provenance naming the acting principal — whose payload carries only the request ID, persona and contact-channel reference the notifier needs to deliver credential instructions. The request's `notification_status` moves `pending` → `sent`/`failed`. The shipped `admin-notifier` worker (see [Activation notifier](#activation-notifier-admin-notifier)) claims events through `ClaimOutboxEvents`, a retry-safe leased claim (`pending` events, `failed` events with attempts left and expired claims are re-claimable, `SKIP LOCKED` prevents double delivery), delivers them through the configured SMTP or webhook channel, and settles them through `RecordNotificationResult`.
- **Agent-assisted bulk enrollment** (officer roles): `POST /v1/enrollment/batches` accepts 1–500 CSV-style JSON rows, validates each row independently and stores an explicit `accepted`/`rejected` status per row. A second, distinct officer must call `POST /v1/enrollment/batches/{id}/confirm` — proposer ≠ confirmer is enforced both in the service and by a database constraint, mirroring the financial-controls dual control. On confirmation each accepted row is enrolled under its own transaction savepoint: a per-row failure is recorded as `failed` with its error and never aborts or silently skips the rest of the batch. Batch-enrolled requests enter the same `pending_verification` pipeline as self-service requests.


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
| `ADMIN_ENROLLMENT_RATE_LIMIT_PER_MINUTE` | Positive fixed-window per-subject/IP rate limit for the public self-service enrollment endpoint; missing or invalid disables enrollment (fail-closed). |

The Keycloak client uses client credentials and invokes the documented organization `invite-user` administrative operation after an atomic PostgreSQL claim. After an authorised invitation/registration result is available, the activation endpoint maps the request’s approved roles to the configured Keycloak organization groups using the documented organization group-membership operation. It sends no account password, raw OIDC user token, refresh token or secret to the database or its HTTP response.

## Activation notifier (admin-notifier)

`cmd/admin-notifier` is the outbox drain worker: without it, activation notices sit at `notification_status = 'pending'` forever. It polls `onboarding_outbox_events`, claims a batch under the 60-second `SKIP LOCKED` lease, delivers each notice through the configured channel and settles every claimed event explicitly — an event is never silently dropped. It runs as a separate process beside `admin-service`, is configured only through the environment and exits at startup when any required value is missing (fail-closed). On SIGTERM it finishes the in-flight batch on a bounded detached context and stops claiming; leases of unsettled events expire and are re-claimed by the next run.

### Notifier operations table

| Variable | Purpose |
|---|---|
| `ADMIN_NOTIFIER_POSTGRES_DSN` | PostgreSQL DSN for the outbox; falls back to `ADMIN_SERVICE_POSTGRES_DSN`. One of the two is required. |
| `ADMIN_NOTIFIER_CHANNEL` | Delivery channel: `smtp` or `webhook`. Required. |
| `ADMIN_NOTIFIER_BATCH_SIZE` | Events claimed per poll (default `25`, 1–500). |
| `ADMIN_NOTIFIER_POLL_INTERVAL` | Delay between claim cycles (default `5s`, 1s–5m). |
| `ADMIN_NOTIFIER_MAX_ATTEMPTS` | Attempt budget per event (default `8`, 1–100). Once exhausted the event stays `failed` as the terminal, operator-visible state and is never reclaimed. |
| `ADMIN_NOTIFIER_METRICS_ADDRESS` | Optional listener exposing expvar counters at `/debug/vars`: `admin_notifier_claimed_total`, `admin_notifier_sent_total`, `admin_notifier_failed_total`, `admin_notifier_retried_total`. |
| `ADMIN_NOTIFIER_SMTP_HOST` / `ADMIN_NOTIFIER_SMTP_PORT` | Submission server and port (default `587` for `starttls`, `465` for `tls`, `25` for `none`). Required host for the `smtp` channel. |
| `ADMIN_NOTIFIER_SMTP_USERNAME` / `ADMIN_NOTIFIER_SMTP_PASSWORD` | Optional SMTP AUTH credentials; must be set together. |
| `ADMIN_NOTIFIER_SMTP_FROM` | Canonical sender address. Required for the `smtp` channel. |
| `ADMIN_NOTIFIER_SMTP_TLS_MODE` | `starttls` (default), `tls` or `none`. `starttls` fails permanently if the server does not offer STARTTLS. |
| `ADMIN_NOTIFIER_WEBHOOK_URL` | Absolute http(s) URL of the notification gateway (for example the SMS/USSD gateway). Required for the `webhook` channel; embedded credentials are rejected. |
| `ADMIN_NOTIFIER_WEBHOOK_HMAC_SECRET` | Optional shared secret; when set, each POST carries `X-Blueeconomy-Signature-256: sha256=<hex HMAC-SHA256 of the raw body>`. |

### Channel contracts

- **SMTP**: the notice is sent to the payload's `contact_reference`, which must be a deliverable e-mail address (officer-path requests fall back to the approved e-mail; self-service requests on `sms`/`ussd`/`app` channels fail permanently on this channel — deploy the webhook channel for those). The message carries the onboarding reference (request ID) and activation timestamp exactly as recorded by the enrollment flow. Recipient rejection (5xx) is permanent; 4xx and network errors are transient.
- **Webhook**: POSTs the platform envelope JSON (`topic`, `event_type`, `classification`, `provenance_principal`, `event_id`, `payload`) with `X-Blueeconomy-Event`, `X-Blueeconomy-Delivery` (event ID, the idempotency key) and the optional HMAC signature header. 2xx settles `sent`; 4xx is a permanent rejection; 5xx and network errors are transient.

### Retry semantics

Each claim increments the event's `attempt`. Transient failures are retried with exponential backoff inside the lease, then settled `failed`-but-reclaimable so the next poll re-claims them. Permanent failures (webhook 4xx, SMTP 5xx, undeliverable payload/reference) settle `failed` immediately. When `attempt` reaches `ADMIN_NOTIFIER_MAX_ATTEMPTS` the next failure settles the terminal `failed` state with an `attempts exhausted` reason; `ClaimOutboxEvents` never re-leases such events. A crashed worker is safe: its claimed events' leases expire after 60 seconds and are re-claimed with a bumped attempt.

## Integration gate

The source has passed deterministic local policy tests. A real release still requires a Ministry-controlled PostgreSQL target, Keycloak realm/service account/organization, APISIX route policy, distinct requester and approver test identities, approved outbound invitation path, role catalogue, audit/logging pipeline and security review. The acceptance test must demonstrate request, maker/checker denial, approval, Keycloak invitation, failure handling, role denial and evidence retention against that authorised environment.
