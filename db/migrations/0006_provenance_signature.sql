-- Fleet provenance signature for onboarding outbox envelopes. Every emitted
-- activation notice is sealed with a JWS (EdDSA/Ed25519) over the
-- JCS-canonicalized notice; the signature travels with the event so the
-- notifier and downstream consumers can verify producer provenance.
ALTER TABLE onboarding_outbox_events
    ADD COLUMN provenance_signature TEXT NOT NULL DEFAULT '' CHECK (length(provenance_signature) <= 2048);
