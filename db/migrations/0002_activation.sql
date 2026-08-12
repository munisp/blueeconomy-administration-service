ALTER TYPE onboarding_request_status ADD VALUE IF NOT EXISTS 'activating' AFTER 'invited';
ALTER TYPE onboarding_request_status ADD VALUE IF NOT EXISTS 'activation_failed' AFTER 'activating';
ALTER TYPE onboarding_request_status ADD VALUE IF NOT EXISTS 'active' AFTER 'activation_failed';

ALTER TABLE onboarding_decisions DROP CONSTRAINT IF EXISTS onboarding_decisions_decision_check;
ALTER TABLE onboarding_decisions ADD CONSTRAINT onboarding_decisions_decision_check
CHECK (decision IN ('approved', 'rejected', 'invited', 'provisioning_failed', 'active', 'activation_failed'));

CREATE UNIQUE INDEX onboarding_one_activation_outcome
ON onboarding_decisions(request_id)
WHERE decision IN ('active', 'activation_failed');
