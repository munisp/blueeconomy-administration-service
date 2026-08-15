CREATE TYPE onboarding_external_operation_kind AS ENUM ('provision', 'activate');
CREATE TYPE onboarding_external_operation_status AS ENUM ('running', 'succeeded', 'failed', 'ambiguous');

CREATE TABLE onboarding_external_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES onboarding_requests(id) ON DELETE RESTRICT,
    operation_kind onboarding_external_operation_kind NOT NULL,
    status onboarding_external_operation_status NOT NULL DEFAULT 'running',
    keycloak_user_id TEXT NOT NULL DEFAULT '' CHECK (length(keycloak_user_id) <= 512),
    attempt INTEGER NOT NULL DEFAULT 1 CHECK (attempt > 0),
    lease_until TIMESTAMPTZ NOT NULL,
    external_reference TEXT NOT NULL DEFAULT '' CHECK (length(external_reference) <= 512),
    last_error TEXT NOT NULL DEFAULT '' CHECK (length(last_error) <= 2048),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (request_id, operation_kind)
);

CREATE INDEX onboarding_external_operations_reconciliation_idx
ON onboarding_external_operations(status, lease_until, updated_at);

CREATE OR REPLACE FUNCTION prevent_external_operation_identity_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.request_id <> NEW.request_id
       OR OLD.operation_kind <> NEW.operation_kind
       OR OLD.keycloak_user_id <> NEW.keycloak_user_id THEN
        RAISE EXCEPTION 'external operation identity fields are immutable';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER external_operation_identity_immutable
BEFORE UPDATE ON onboarding_external_operations
FOR EACH ROW EXECUTE FUNCTION prevent_external_operation_identity_mutation();

ALTER TABLE onboarding_decisions DROP CONSTRAINT IF EXISTS onboarding_decisions_decision_check;
ALTER TABLE onboarding_decisions ADD CONSTRAINT onboarding_decisions_decision_check
CHECK (decision IN ('approved', 'rejected', 'invited', 'provisioning_failed', 'active', 'activation_failed', 'provision_ambiguous', 'activation_ambiguous'));

ALTER TYPE onboarding_request_status ADD VALUE IF NOT EXISTS 'provisioning_ambiguous' AFTER 'provisioning_failed';
ALTER TYPE onboarding_request_status ADD VALUE IF NOT EXISTS 'activation_ambiguous' AFTER 'activation_failed';
