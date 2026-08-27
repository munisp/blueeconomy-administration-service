# Local PostgreSQL–Keycloak Integration Suite

`run-local.sh` is a **real local integration test**, not a mock. It creates short-lived containers for PostgreSQL 16, Keycloak 26.7.1 and Mailpit, generates a one-day localhost TLS certificate and random local-only secrets, applies the real service migrations, starts the actual Go central-administration service and invokes its HTTP API. The suite uses Keycloak Administrative REST endpoints, client credentials, organization invitations and organization-group membership operations over TLS verified by the generated local CA file.

## Run

```bash
cd blueeconomy-administration-service
./integration/run-local.sh
```

Docker must be available. The suite requires `curl`, `jq`, `openssl`, Go, and Docker Compose. It binds only `127.0.0.1` ports while it runs, then stops containers and removes the test volume through its exit trap. The non-secret result survives at `integration/results/local-integration-result.json`; the generated `.env`, key and certificate are ignored by Git and must not be reused.

## Assertions

The script proves this ordered path against actual local components:

1. Service-side authorization denials: an authenticated subject with no role assertion receives 403, a read-only observer role receives 403 on a mutating route, and an unknown route receives 403.
2. A requester submits a persisted onboarding request to the Go service.
3. A distinct actor approves it, satisfying the service maker/checker guard.
4. The service acquires a Keycloak service-account token through HTTPS and invokes Keycloak organization invitation.
5. Keycloak sends an invitation message to the local SMTP service; the suite verifies one or more captured messages.
6. The suite creates the local fixture user through Keycloak, associates it with the local organization, then calls the service activation endpoint.
7. The service maps the approved role to the actual local Keycloak organization group.
8. PostgreSQL shows the immutable decision sequence `approved,invited,active`, final state `active`, and Keycloak reports the fixture user in the expected organization group.

## Boundary

The suite does not connect to Ministry Keycloak, PostgreSQL, APISIX, Wazuh, OpenCTI, Kafka, Temporal, Mojaloop, TigerBeetle or partner systems. It generates local test fixtures only to exercise the real open-source integration protocol and deletes the containerized state on completion. It is not production acceptance and does not authorize real stakeholder invitations.
