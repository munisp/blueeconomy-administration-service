CREATE TYPE privacy_activity_status AS ENUM (
    'draft',
    'owner_attested',
    'dpo_review',
    'conditionally_approved',
    'approved',
    'rejected',
    'expired'
);

CREATE TABLE privacy_processing_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    activity_key TEXT NOT NULL UNIQUE CHECK (activity_key ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    service_name TEXT NOT NULL CHECK (service_name ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    purpose TEXT NOT NULL CHECK (length(purpose) BETWEEN 1 AND 2048),
    data_classifications TEXT[] NOT NULL CHECK (cardinality(data_classifications) BETWEEN 1 AND 16),
    external_recipients TEXT[] NOT NULL DEFAULT '{}'::TEXT[] CHECK (cardinality(external_recipients) <= 32),
    evidence_sha256 TEXT NOT NULL CHECK (evidence_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    requester_subject TEXT NOT NULL CHECK (length(requester_subject) BETWEEN 1 AND 512),
    owner_subject TEXT NOT NULL CHECK (length(owner_subject) BETWEEN 1 AND 512),
    status privacy_activity_status NOT NULL DEFAULT 'draft',
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    approval_conditions TEXT NOT NULL DEFAULT '' CHECK (length(approval_conditions) <= 4096),
    approval_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((status = 'conditionally_approved') = (approval_expires_at IS NOT NULL))
);

CREATE TABLE privacy_activity_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    activity_id UUID NOT NULL REFERENCES privacy_processing_activities(id) ON DELETE RESTRICT,
    activity_version BIGINT NOT NULL CHECK (activity_version > 0),
    decision TEXT NOT NULL CHECK (decision IN ('owner_attested', 'dpo_review', 'conditionally_approved', 'approved', 'rejected', 'expired')),
    actor_subject TEXT NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 512),
    reason TEXT NOT NULL DEFAULT '' CHECK (length(reason) <= 4096),
    evidence_sha256 TEXT NOT NULL CHECK (evidence_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    approval_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX privacy_processing_activities_status_expiry_idx
ON privacy_processing_activities(status, approval_expires_at);

CREATE INDEX privacy_activity_decisions_activity_created_idx
ON privacy_activity_decisions(activity_id, created_at);

CREATE OR REPLACE FUNCTION prevent_privacy_activity_scope_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.activity_key <> NEW.activity_key
       OR OLD.service_name <> NEW.service_name
       OR OLD.purpose <> NEW.purpose
       OR OLD.data_classifications <> NEW.data_classifications
       OR OLD.external_recipients <> NEW.external_recipients
       OR OLD.evidence_sha256 <> NEW.evidence_sha256
       OR OLD.requester_subject <> NEW.requester_subject
       OR OLD.owner_subject <> NEW.owner_subject THEN
        RAISE EXCEPTION 'privacy activity scope fields are immutable; create a replacement activity for a material change';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'privacy activity version must advance by exactly one';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER privacy_activity_scope_immutable
BEFORE UPDATE ON privacy_processing_activities
FOR EACH ROW EXECUTE FUNCTION prevent_privacy_activity_scope_mutation();
