package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func (store *Store) CreatePrivacyActivity(ctx context.Context, input CreatePrivacyActivityInput, requesterSubject string) (PrivacyProcessingActivity, error) {
	if err := validateSubject("requester_subject", requesterSubject); err != nil {
		return PrivacyProcessingActivity{}, err
	}
	const query = `
		INSERT INTO privacy_processing_activities (
			activity_key, service_name, purpose, data_classifications, external_recipients,
			evidence_sha256, requester_subject, owner_subject
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id::text, activity_key, service_name, purpose, data_classifications, external_recipients,
			evidence_sha256, requester_subject, owner_subject, status, version, approval_conditions,
			approval_expires_at, created_at, updated_at`
	return scanPrivacyActivity(store.pool.QueryRow(ctx, query,
		input.ActivityKey, input.ServiceName, input.Purpose, input.DataClassifications, input.ExternalRecipients,
		input.EvidenceSHA256, requesterSubject, input.OwnerSubject,
	))
}

func (store *Store) GetPrivacyActivity(ctx context.Context, id string) (PrivacyProcessingActivity, error) {
	const query = `
		SELECT id::text, activity_key, service_name, purpose, data_classifications, external_recipients,
		       evidence_sha256, requester_subject, owner_subject, status, version, approval_conditions,
		       approval_expires_at, created_at, updated_at
		FROM privacy_processing_activities WHERE id = $1`
	return scanPrivacyActivity(store.pool.QueryRow(ctx, query, id))
}

func getPrivacyActivityForUpdate(ctx context.Context, transaction pgx.Tx, id string) (PrivacyProcessingActivity, error) {
	const query = `
		SELECT id::text, activity_key, service_name, purpose, data_classifications, external_recipients,
		       evidence_sha256, requester_subject, owner_subject, status, version, approval_conditions,
		       approval_expires_at, created_at, updated_at
		FROM privacy_processing_activities WHERE id = $1 FOR UPDATE`
	return scanPrivacyActivity(transaction.QueryRow(ctx, query, id))
}

func (store *Store) AttestPrivacyActivity(ctx context.Context, id, actorSubject string, input PrivacyWorkflowInput) (PrivacyProcessingActivity, error) {
	if err := validateSubject("actor_subject", actorSubject); err != nil {
		return PrivacyProcessingActivity{}, err
	}
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return PrivacyProcessingActivity{}, fmt.Errorf("begin privacy attestation transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	activity, err := getPrivacyActivityForUpdate(ctx, transaction, id)
	if err != nil {
		return PrivacyProcessingActivity{}, fmt.Errorf("load privacy activity: %w", err)
	}
	if activity.Status != PrivacyActivityDraft || activity.Version != input.ExpectedVersion {
		return PrivacyProcessingActivity{}, errors.New("privacy activity is not at the expected draft version")
	}
	if actorSubject != activity.OwnerSubject {
		return PrivacyProcessingActivity{}, errors.New("only the recorded privacy activity owner may attest")
	}
	return transitionPrivacyActivity(ctx, transaction, activity, PrivacyActivityOwnerAttested, actorSubject, input.Reason, input.EvidenceSHA256, "", nil)
}

func (store *Store) SubmitPrivacyDPOReview(ctx context.Context, id, actorSubject string, input PrivacyWorkflowInput) (PrivacyProcessingActivity, error) {
	if err := validateSubject("actor_subject", actorSubject); err != nil {
		return PrivacyProcessingActivity{}, err
	}
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return PrivacyProcessingActivity{}, fmt.Errorf("begin privacy review transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	activity, err := getPrivacyActivityForUpdate(ctx, transaction, id)
	if err != nil {
		return PrivacyProcessingActivity{}, fmt.Errorf("load privacy activity: %w", err)
	}
	if activity.Status != PrivacyActivityOwnerAttested || activity.Version != input.ExpectedVersion {
		return PrivacyProcessingActivity{}, errors.New("privacy activity is not at the expected owner-attested version")
	}
	if actorSubject != activity.OwnerSubject {
		return PrivacyProcessingActivity{}, errors.New("only the recorded privacy activity owner may submit DPO review")
	}
	return transitionPrivacyActivity(ctx, transaction, activity, PrivacyActivityDPOReview, actorSubject, input.Reason, input.EvidenceSHA256, "", nil)
}

func (store *Store) DecidePrivacyActivity(ctx context.Context, id, actorSubject string, input PrivacyDecisionInput) (PrivacyProcessingActivity, error) {
	if err := validateSubject("actor_subject", actorSubject); err != nil {
		return PrivacyProcessingActivity{}, err
	}
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return PrivacyProcessingActivity{}, fmt.Errorf("begin DPO decision transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	activity, err := getPrivacyActivityForUpdate(ctx, transaction, id)
	if err != nil {
		return PrivacyProcessingActivity{}, fmt.Errorf("load privacy activity: %w", err)
	}
	if activity.Status != PrivacyActivityDPOReview || activity.Version != input.ExpectedVersion {
		return PrivacyProcessingActivity{}, errors.New("privacy activity is not at the expected DPO-review version")
	}
	if actorSubject == activity.RequesterSubject || actorSubject == activity.OwnerSubject {
		return PrivacyProcessingActivity{}, errors.New("maker/checker violation: requester or owner cannot make the DPO decision")
	}
	status := PrivacyActivityStatus(input.Decision)
	conditions := ""
	if status == PrivacyActivityConditionallyApproved {
		conditions = input.Reason
	}
	return transitionPrivacyActivity(ctx, transaction, activity, status, actorSubject, input.Reason, input.EvidenceSHA256, conditions, input.ApprovalExpiresAt)
}

func transitionPrivacyActivity(ctx context.Context, transaction pgx.Tx, activity PrivacyProcessingActivity, status PrivacyActivityStatus, actorSubject, reason, evidenceSHA256, conditions string, expiresAt any) (PrivacyProcessingActivity, error) {
	const update = `
		UPDATE privacy_processing_activities
		SET status = $2, version = version + 1, approval_conditions = $3, approval_expires_at = $4
		WHERE id = $1
		RETURNING id::text, activity_key, service_name, purpose, data_classifications, external_recipients,
			evidence_sha256, requester_subject, owner_subject, status, version, approval_conditions,
			approval_expires_at, created_at, updated_at`
	updated, err := scanPrivacyActivity(transaction.QueryRow(ctx, update, activity.ID, status, conditions, expiresAt))
	if err != nil {
		return PrivacyProcessingActivity{}, fmt.Errorf("update privacy activity: %w", err)
	}
	const evidence = `
		INSERT INTO privacy_activity_decisions (
			activity_id, activity_version, decision, actor_subject, reason, evidence_sha256, approval_expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	if _, err := transaction.Exec(ctx, evidence, activity.ID, updated.Version, status, actorSubject, reason, evidenceSHA256, expiresAt); err != nil {
		return PrivacyProcessingActivity{}, fmt.Errorf("write privacy decision evidence: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return PrivacyProcessingActivity{}, fmt.Errorf("commit privacy transition: %w", err)
	}
	return updated, nil
}

func scanPrivacyActivity(row pgx.Row) (PrivacyProcessingActivity, error) {
	var activity PrivacyProcessingActivity
	if err := row.Scan(
		&activity.ID,
		&activity.ActivityKey,
		&activity.ServiceName,
		&activity.Purpose,
		&activity.DataClassifications,
		&activity.ExternalRecipients,
		&activity.EvidenceSHA256,
		&activity.RequesterSubject,
		&activity.OwnerSubject,
		&activity.Status,
		&activity.Version,
		&activity.ApprovalConditions,
		&activity.ApprovalExpiresAt,
		&activity.CreatedAt,
		&activity.UpdatedAt,
	); err != nil {
		return PrivacyProcessingActivity{}, err
	}
	return activity, nil
}
