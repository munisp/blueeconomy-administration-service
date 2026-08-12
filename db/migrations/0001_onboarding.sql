CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE onboarding_request_status AS ENUM ('submitted', 'approved', 'provisioning', 'rejected', 'invited', 'provisioning_failed');

CREATE TABLE onboarding_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id TEXT NOT NULL CHECK (length(organization_id) BETWEEN 1 AND 255),
    email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
    first_name TEXT NOT NULL CHECK (length(first_name) BETWEEN 1 AND 255),
    last_name TEXT NOT NULL CHECK (length(last_name) BETWEEN 1 AND 255),
    requested_roles TEXT[] NOT NULL CHECK (cardinality(requested_roles) > 0),
    requester_subject TEXT NOT NULL CHECK (length(requester_subject) BETWEEN 1 AND 512),
    status onboarding_request_status NOT NULL DEFAULT 'submitted',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, email, status) DEFERRABLE INITIALLY IMMEDIATE
);

CREATE TABLE onboarding_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES onboarding_requests(id) ON DELETE RESTRICT,
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected', 'invited', 'provisioning_failed')),
    actor_subject TEXT NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 512),
    reason TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX onboarding_one_approval_or_rejection
ON onboarding_decisions(request_id)
WHERE decision IN ('approved', 'rejected');

CREATE INDEX onboarding_requests_status_created_at_idx
ON onboarding_requests(status, created_at);

CREATE OR REPLACE FUNCTION prevent_onboarding_request_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.organization_id <> NEW.organization_id
       OR OLD.email <> NEW.email
       OR OLD.first_name <> NEW.first_name
       OR OLD.last_name <> NEW.last_name
       OR OLD.requested_roles <> NEW.requested_roles
       OR OLD.requester_subject <> NEW.requester_subject THEN
        RAISE EXCEPTION 'onboarding request identity and access fields are immutable';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER onboarding_request_immutable_fields
BEFORE UPDATE ON onboarding_requests
FOR EACH ROW EXECUTE FUNCTION prevent_onboarding_request_mutation();
