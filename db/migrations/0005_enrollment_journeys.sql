-- Enrollment journeys: self-service enrollment, KYC identity proofing,
-- activation notification outbox and dual-controlled batch enrollment.
-- All new paths are fail-closed: self-service requests enter
-- pending_verification and can only reach a decision after an officer records
-- an identity verification outcome.

ALTER TYPE onboarding_request_status ADD VALUE IF NOT EXISTS 'pending_verification';
ALTER TYPE onboarding_request_status ADD VALUE IF NOT EXISTS 'identity_review';
ALTER TYPE onboarding_request_status ADD VALUE IF NOT EXISTS 'identity_verified';
ALTER TYPE onboarding_request_status ADD VALUE IF NOT EXISTS 'identity_rejected';

ALTER TABLE onboarding_requests
    ADD COLUMN persona TEXT NOT NULL DEFAULT ''
        CHECK (persona = '' OR persona IN ('trucker', 'ferry-passenger', 'operator', 'fisher', 'seafarer-trainee', 'beneficiary', 'exporter', 'processor', 'fleet-operator')),
    ADD COLUMN contact_channel TEXT NOT NULL DEFAULT ''
        CHECK (contact_channel = '' OR contact_channel IN ('sms', 'ussd', 'email', 'app')),
    ADD COLUMN contact_reference TEXT NOT NULL DEFAULT '' CHECK (length(contact_reference) <= 320),
    ADD COLUMN notification_status TEXT NOT NULL DEFAULT ''
        CHECK (notification_status IN ('', 'pending', 'sent', 'failed'));

-- The pre-decision enrollment states exist only for self-service personas.
ALTER TABLE onboarding_requests ADD CONSTRAINT onboarding_requests_enrollment_state_persona
CHECK (status NOT IN ('pending_verification', 'identity_review', 'identity_verified', 'identity_rejected') OR persona <> '');

-- Self-service rows may legitimately have no e-mail (sms/ussd/app channels)
-- and no pre-approved role set; officer-submitted rows are unchanged.
ALTER TABLE onboarding_requests DROP CONSTRAINT onboarding_requests_email_check;
ALTER TABLE onboarding_requests ADD CONSTRAINT onboarding_requests_email_check
CHECK ((length(email) BETWEEN 3 AND 320) OR (persona <> '' AND email = ''));

ALTER TABLE onboarding_requests DROP CONSTRAINT onboarding_requests_requested_roles_check;
ALTER TABLE onboarding_requests ADD CONSTRAINT onboarding_requests_requested_roles_check
CHECK (cardinality(requested_roles) > 0 OR persona <> '');

-- Replace the officer-path duplicate guard with per-path partial indexes so
-- self-service rows deduplicate on their contact reference instead of e-mail.
ALTER TABLE onboarding_requests DROP CONSTRAINT onboarding_requests_organization_id_email_status_key;
CREATE UNIQUE INDEX onboarding_requests_officer_dedup
ON onboarding_requests(organization_id, email, status)
WHERE persona = '';
CREATE UNIQUE INDEX onboarding_requests_enrollment_dedup
ON onboarding_requests(organization_id, contact_channel, contact_reference, status)
WHERE persona <> '';

-- Extend the immutable-field guard to the enrollment identity fields.
CREATE OR REPLACE FUNCTION prevent_onboarding_request_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.organization_id <> NEW.organization_id
       OR OLD.email <> NEW.email
       OR OLD.first_name <> NEW.first_name
       OR OLD.last_name <> NEW.last_name
       OR OLD.requested_roles <> NEW.requested_roles
       OR OLD.requester_subject <> NEW.requester_subject
       OR OLD.persona <> NEW.persona
       OR OLD.contact_channel <> NEW.contact_channel
       OR OLD.contact_reference <> NEW.contact_reference THEN
        RAISE EXCEPTION 'onboarding request identity and access fields are immutable';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Identity-proofing audit transitions join the decision evidence stream.
ALTER TABLE onboarding_decisions DROP CONSTRAINT IF EXISTS onboarding_decisions_decision_check;
ALTER TABLE onboarding_decisions ADD CONSTRAINT onboarding_decisions_decision_check
CHECK (decision IN ('approved', 'rejected', 'invited', 'provisioning_failed', 'active', 'activation_failed',
                    'provision_ambiguous', 'activation_ambiguous',
                    'identity_review', 'identity_verified', 'identity_rejected'));

-- KYC identity-proofing evidence. Only the sha256 digest of the document
-- reference is stored; raw document numbers must never reach this table.
CREATE TABLE onboarding_kyc_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES onboarding_requests(id) ON DELETE RESTRICT,
    document_type TEXT NOT NULL
        CHECK (document_type IN ('passport', 'national-id', 'drivers-license', 'seafarers-discharge-book', 'voter-card', 'birth-certificate')),
    document_reference_sha256 TEXT NOT NULL CHECK (document_reference_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    outcome TEXT NOT NULL CHECK (outcome IN ('identity_verified', 'identity_rejected')),
    officer_subject TEXT NOT NULL CHECK (length(officer_subject) BETWEEN 1 AND 512),
    reason TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One identity-proofing outcome per request keeps the evidence unambiguous.
CREATE UNIQUE INDEX onboarding_kyc_one_outcome
ON onboarding_kyc_reviews(request_id);

CREATE INDEX onboarding_kyc_reviews_request_created_idx
ON onboarding_kyc_reviews(request_id, created_at);

-- Platform-envelope outbox for activation notifications. The notifier
-- (USSD/SMS gateway) claims pending events through the retry-safe lease and
-- records the delivery result; no SMS client lives in this service.
CREATE TYPE onboarding_outbox_status AS ENUM ('pending', 'claimed', 'sent', 'failed');

CREATE TABLE onboarding_outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES onboarding_requests(id) ON DELETE RESTRICT,
    topic TEXT NOT NULL CHECK (topic = 'platform.onboarding.v1'),
    event_type TEXT NOT NULL CHECK (event_type = 'onboarding.activated.v1'),
    classification TEXT NOT NULL CHECK (classification = 'CONFIDENTIAL'),
    provenance_principal TEXT NOT NULL CHECK (length(provenance_principal) BETWEEN 1 AND 512),
    payload JSONB NOT NULL,
    status onboarding_outbox_status NOT NULL DEFAULT 'pending',
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    lease_until TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '' CHECK (length(last_error) <= 2048),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX onboarding_outbox_one_activation
ON onboarding_outbox_events(request_id)
WHERE event_type = 'onboarding.activated.v1';

CREATE INDEX onboarding_outbox_claim_idx
ON onboarding_outbox_events(status, lease_until, created_at);

CREATE OR REPLACE FUNCTION touch_outbox_event_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER outbox_event_touch_updated_at
BEFORE UPDATE ON onboarding_outbox_events
FOR EACH ROW EXECUTE FUNCTION touch_outbox_event_updated_at();

-- Fixed-window rate-limit buckets for the public self-service endpoint.
CREATE TABLE enrollment_rate_limits (
    bucket_key TEXT NOT NULL CHECK (length(bucket_key) BETWEEN 1 AND 512),
    window_start TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    PRIMARY KEY (bucket_key, window_start)
);

-- Agent-assisted batch enrollment with database-enforced dual control.
CREATE TYPE enrollment_batch_status AS ENUM ('proposed', 'confirmed');

CREATE TABLE enrollment_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposer_subject TEXT NOT NULL CHECK (length(proposer_subject) BETWEEN 1 AND 512),
    confirmer_subject TEXT NOT NULL DEFAULT '' CHECK (length(confirmer_subject) <= 512),
    status enrollment_batch_status NOT NULL DEFAULT 'proposed',
    row_count INTEGER NOT NULL CHECK (row_count BETWEEN 1 AND 500),
    accepted_count INTEGER NOT NULL DEFAULT 0 CHECK (accepted_count >= 0),
    enrolled_count INTEGER NOT NULL DEFAULT 0 CHECK (enrolled_count >= 0),
    failed_count INTEGER NOT NULL DEFAULT 0 CHECK (failed_count >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at TIMESTAMPTZ,
    CHECK (confirmer_subject = '' OR confirmer_subject <> proposer_subject)
);

CREATE TABLE enrollment_batch_rows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES enrollment_batches(id) ON DELETE RESTRICT,
    row_index INTEGER NOT NULL CHECK (row_index BETWEEN 0 AND 499),
    -- Row payloads are length-bounded only: rejected rows must be storable
    -- with their invalid values so per-row failures are explicit. Only rows
    -- that passed validation (status 'accepted') can be enrolled into
    -- onboarding_requests, where the strict catalogues are enforced.
    persona TEXT NOT NULL CHECK (length(persona) <= 64),
    contact_channel TEXT NOT NULL CHECK (length(contact_channel) <= 16),
    contact_reference TEXT NOT NULL CHECK (length(contact_reference) <= 320),
    first_name TEXT NOT NULL DEFAULT '' CHECK (length(first_name) <= 255),
    last_name TEXT NOT NULL DEFAULT '' CHECK (length(last_name) <= 255),
    email TEXT NOT NULL DEFAULT '' CHECK (length(email) <= 320),
    status TEXT NOT NULL CHECK (status IN ('accepted', 'rejected', 'enrolled', 'failed')),
    error TEXT NOT NULL DEFAULT '' CHECK (length(error) <= 1024),
    request_id UUID REFERENCES onboarding_requests(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (batch_id, row_index)
);

CREATE INDEX enrollment_batch_rows_batch_status_idx
ON enrollment_batch_rows(batch_id, status);
