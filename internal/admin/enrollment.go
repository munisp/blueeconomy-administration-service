package admin

import (
	"github.com/munisp/blueeconomy-administration-service/internal/provenance"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AllowEnrollmentRequest implements the strict fixed-window rate limit for
// the public self-service endpoint. The bucket counter is incremented
// atomically; callers are admitted only while the window count stays within
// the configured limit. Any storage error fails closed (the caller is denied).
func (store *Store) AllowEnrollmentRequest(ctx context.Context, bucketKey string, windowStart time.Time, limit int) (bool, error) {
	if limit <= 0 {
		return false, errors.New("enrollment rate limit is not configured")
	}
	const query = `
	INSERT INTO enrollment_rate_limits (bucket_key, window_start, request_count)
	VALUES ($1, $2, 1)
	ON CONFLICT (bucket_key, window_start)
	DO UPDATE SET request_count = enrollment_rate_limits.request_count + 1
	RETURNING request_count`
	var count int
	if err := store.pool.QueryRow(ctx, query, bucketKey, windowStart).Scan(&count); err != nil {
		return false, fmt.Errorf("claim enrollment rate-limit window: %w", err)
	}
	return count <= limit, nil
}

// CreateEnrollment records one self-service enrollment request. It always
// lands in pending_verification: there is no query path from this insert to
// provisioning without an officer identity review and decision.
func (store *Store) CreateEnrollment(ctx context.Context, organizationID string, input EnrollmentSubmitInput, requesterSubject string) (OnboardingRequest, error) {
	const query = `
	INSERT INTO onboarding_requests (organization_id, email, first_name, last_name, requested_roles, requester_subject, persona, contact_channel, contact_reference, status)
	VALUES ($1, $2, $3, $4, '{}', $5, $6, $7, $8, 'pending_verification')
	RETURNING id::text, organization_id, email, first_name, last_name, requested_roles, requester_subject, status, persona, contact_channel, contact_reference, notification_status, created_at, updated_at`
	return scanRequest(store.pool.QueryRow(ctx, query,
		organizationID, input.Email, input.FirstName, input.LastName, requesterSubject,
		input.Persona, input.ContactChannel, input.ContactReference,
	))
}

// StartIdentityReview moves a pending self-service enrollment request into
// identity review and writes the audit row for the transition.
func (store *Store) StartIdentityReview(ctx context.Context, id, officerSubject string) (OnboardingRequest, error) {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return OnboardingRequest{}, fmt.Errorf("begin identity-review transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	request, err := store.GetForUpdate(ctx, transaction, id)
	if err != nil {
		return OnboardingRequest{}, fmt.Errorf("load enrollment request: %w", err)
	}
	if err := request.CanStartIdentityReview(); err != nil {
		return OnboardingRequest{}, err
	}
	if _, err := transaction.Exec(ctx, `UPDATE onboarding_requests SET status = $2 WHERE id = $1`, id, StatusIdentityReview); err != nil {
		return OnboardingRequest{}, fmt.Errorf("update enrollment status: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO onboarding_decisions (request_id, decision, actor_subject, reason) VALUES ($1, $2, $3, $4)`, id, StatusIdentityReview, officerSubject, "identity proofing started"); err != nil {
		return OnboardingRequest{}, fmt.Errorf("write identity-review audit row: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return OnboardingRequest{}, fmt.Errorf("commit identity-review transition: %w", err)
	}
	request.Status = StatusIdentityReview
	request.UpdatedAt = time.Now().UTC()
	return request, nil
}

// RecordIdentityVerification stores the officer's identity-proofing outcome:
// the request leaves identity review as identity_verified or
// identity_rejected, the KYC evidence row keeps only the document reference
// digest, and the audit row records who decided and when.
func (store *Store) RecordIdentityVerification(ctx context.Context, id, officerSubject string, input IdentityVerificationInput) (OnboardingRequest, error) {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return OnboardingRequest{}, fmt.Errorf("begin identity-verification transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	request, err := store.GetForUpdate(ctx, transaction, id)
	if err != nil {
		return OnboardingRequest{}, fmt.Errorf("load enrollment request: %w", err)
	}
	if err := request.CanRecordIdentityOutcome(); err != nil {
		return OnboardingRequest{}, err
	}
	status := StatusIdentityVerified
	switch input.Outcome {
	case string(StatusIdentityVerified):
	case string(StatusIdentityRejected):
		status = StatusIdentityRejected
	default:
		return OnboardingRequest{}, errors.New("outcome must be identity_verified or identity_rejected")
	}
	if _, err := transaction.Exec(ctx, `UPDATE onboarding_requests SET status = $2 WHERE id = $1`, id, status); err != nil {
		return OnboardingRequest{}, fmt.Errorf("update enrollment status: %w", err)
	}
	const reviewQuery = `
	INSERT INTO onboarding_kyc_reviews (request_id, document_type, document_reference_sha256, outcome, officer_subject, reason)
	VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := transaction.Exec(ctx, reviewQuery, id, input.DocumentType, input.DocumentReferenceSHA256, status, officerSubject, input.Reason); err != nil {
		return OnboardingRequest{}, fmt.Errorf("write kyc review evidence: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO onboarding_decisions (request_id, decision, actor_subject, reason) VALUES ($1, $2, $3, $4)`, id, status, officerSubject, input.Reason); err != nil {
		return OnboardingRequest{}, fmt.Errorf("write identity-verification audit row: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return OnboardingRequest{}, fmt.Errorf("commit identity-verification transition: %w", err)
	}
	request.Status = status
	request.UpdatedAt = time.Now().UTC()
	return request, nil
}

// insertActivationNotice emits the platform-envelope outbox event for a
// completed activation and marks the request notification as pending. It runs
// inside the activation transaction, so an activation can never be recorded
// without its notification event. The notice is sealed with the fleet
// provenance signature; without a signer the activation fails closed.
func insertActivationNotice(ctx context.Context, transaction pgx.Tx, signer *provenance.Signer, requestID, principal string) error {
	if signer == nil {
		return errors.New("provenance signer is required")
	}
	const loadQuery = `
	SELECT id::text, organization_id, email, first_name, last_name, requested_roles, requester_subject, status, persona, contact_channel, contact_reference, notification_status, created_at, updated_at
	FROM onboarding_requests WHERE id = $1`
	request, err := scanRequest(transaction.QueryRow(ctx, loadQuery, requestID))
	if err != nil {
		return fmt.Errorf("load activated request: %w", err)
	}
	notice := NewActivationNotice(request, principal, time.Now().UTC())
	signature, err := signer.SignEnvelope(notice)
	if err != nil {
		return fmt.Errorf("sign activation notice provenance: %w", err)
	}
	notice.Provenance.Signature = signature
	payload, err := json.Marshal(notice.Payload)
	if err != nil {
		return fmt.Errorf("encode activation notice payload: %w", err)
	}
	const insertQuery = `
	INSERT INTO onboarding_outbox_events (request_id, topic, event_type, classification, provenance_principal, provenance_signature, payload)
	VALUES ($1, $2, $3, $4, $5, $6, $7)`
	if _, err := transaction.Exec(ctx, insertQuery, requestID, notice.Topic, notice.EventType, notice.Classification, notice.ProvenancePrincipal, notice.Provenance.Signature, payload); err != nil {
		return fmt.Errorf("write activation outbox event: %w", err)
	}
	if _, err := transaction.Exec(ctx, `UPDATE onboarding_requests SET notification_status = $2 WHERE id = $1`, requestID, NotificationPending); err != nil {
		return fmt.Errorf("mark activation notification pending: %w", err)
	}
	return nil
}

// ClaimOutboxEvents is the retry-safe claim path for the notifier: pending
// events, failed events with attempts left, and claimed events whose lease
// expired (crashed workers) are atomically re-leased. SKIP LOCKED keeps
// concurrent claimers from double-delivering. Events that already exhausted
// maxAttempts stay failed as the terminal, operator-visible state and are
// never reclaimed.
func (store *Store) ClaimOutboxEvents(ctx context.Context, limit, maxAttempts int) ([]OutboxEvent, error) {
	if limit <= 0 || limit > 500 {
		return nil, errors.New("claim limit must be between 1 and 500")
	}
	if maxAttempts <= 0 {
		return nil, errors.New("max attempts must be positive")
	}
	const query = `
	UPDATE onboarding_outbox_events
	SET status = 'claimed', attempt = attempt + 1, lease_until = now() + interval '60 seconds'
	WHERE id IN (
		SELECT id FROM onboarding_outbox_events
		WHERE status = 'pending'
			OR (status = 'failed' AND attempt < $2)
			OR (status = 'claimed' AND lease_until < now() AND attempt < $2)
		ORDER BY created_at
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	)
	RETURNING id::text, request_id::text, topic, event_type, classification, provenance_principal, provenance_signature, payload, status, attempt, created_at`
	rows, err := store.pool.Query(ctx, query, limit, maxAttempts)
	if err != nil {
		return nil, fmt.Errorf("claim outbox events: %w", err)
	}
	defer rows.Close()
	var events []OutboxEvent
	for rows.Next() {
		var event OutboxEvent
		if err := rows.Scan(
			&event.ID,
			&event.RequestID,
			&event.Topic,
			&event.EventType,
			&event.Classification,
			&event.ProvenancePrincipal,
			&event.Signature,
			&event.Payload,
			&event.Status,
			&event.Attempt,
			&event.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan claimed outbox event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claimed outbox events: %w", err)
	}
	return events, nil
}

// RecordNotificationResult settles a claimed outbox event as sent or failed
// and mirrors the outcome onto the request's notification_status. Only a
// claimed event can be settled, so a stale or double settlement fails closed;
// failed events stay claimable for retry.
func (store *Store) RecordNotificationResult(ctx context.Context, eventID string, success bool, reason string) error {
	status := OutboxSent
	notificationStatus := NotificationSent
	if !success {
		status = OutboxFailed
		notificationStatus = NotificationFailed
	}
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin notification-result transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	command, err := transaction.Exec(ctx, `UPDATE onboarding_outbox_events SET status = $2, last_error = $3, lease_until = NULL WHERE id = $1 AND status = 'claimed'`, eventID, status, reason)
	if err != nil {
		return fmt.Errorf("settle outbox event: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("outbox event is not in %q state", OutboxClaimed)
	}
	const mirrorQuery = `
	UPDATE onboarding_requests SET notification_status = $2
	WHERE id = (SELECT request_id FROM onboarding_outbox_events WHERE id = $1)`
	if _, err := transaction.Exec(ctx, mirrorQuery, eventID, notificationStatus); err != nil {
		return fmt.Errorf("mirror notification status: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit notification result: %w", err)
	}
	return nil
}

// CreateBatch records one agent-assisted enrollment batch in proposed state.
// Rows were validated independently by the caller; each row is stored with an
// explicit accepted/rejected status so validation failures are never silent.
func (store *Store) CreateBatch(ctx context.Context, proposerSubject string, rows []EnrollmentSubmitInput, results []error) (EnrollmentBatch, []EnrollmentBatchRow, error) {
	if len(rows) != len(results) || len(rows) == 0 || len(rows) > MaxEnrollmentBatchRows {
		return EnrollmentBatch{}, nil, fmt.Errorf("a batch must contain between 1 and %d validated rows", MaxEnrollmentBatchRows)
	}
	accepted := 0
	for _, result := range results {
		if result == nil {
			accepted++
		}
	}
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return EnrollmentBatch{}, nil, fmt.Errorf("begin batch transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	const batchQuery = `
	INSERT INTO enrollment_batches (proposer_subject, row_count, accepted_count)
	VALUES ($1, $2, $3)
	RETURNING id::text, proposer_subject, confirmer_subject, status, row_count, accepted_count, enrolled_count, failed_count, created_at, confirmed_at`
	batch, err := scanBatch(transaction.QueryRow(ctx, batchQuery, proposerSubject, len(rows), accepted))
	if err != nil {
		return EnrollmentBatch{}, nil, fmt.Errorf("write enrollment batch: %w", err)
	}
	const rowQuery = `
	INSERT INTO enrollment_batch_rows (batch_id, row_index, persona, contact_channel, contact_reference, first_name, last_name, email, status, error)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	records := make([]EnrollmentBatchRow, len(rows))
	for index, row := range rows {
		status := BatchRowAccepted
		message := ""
		if results[index] != nil {
			status = BatchRowRejected
			message = truncateBatchError(results[index].Error())
		}
		if _, err := transaction.Exec(ctx, rowQuery, batch.ID, index, row.Persona, row.ContactChannel, row.ContactReference, row.FirstName, row.LastName, row.Email, status, message); err != nil {
			return EnrollmentBatch{}, nil, fmt.Errorf("write enrollment batch row %d: %w", index, err)
		}
		records[index] = EnrollmentBatchRow{RowIndex: index, Status: status, Error: message}
	}
	if err := transaction.Commit(ctx); err != nil {
		return EnrollmentBatch{}, nil, fmt.Errorf("commit enrollment batch: %w", err)
	}
	return batch, records, nil
}

// ConfirmBatch applies dual control and enrollment in one serializable
// transaction: the confirming officer must differ from the proposer (enforced
// here and by the database constraint), and every accepted row is enrolled
// under its own savepoint so one row's failure is recorded explicitly and
// never aborts or silently skips the rest of the batch.
func (store *Store) ConfirmBatch(ctx context.Context, id, organizationID, confirmerSubject string) (EnrollmentBatch, []EnrollmentBatchRow, error) {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return EnrollmentBatch{}, nil, fmt.Errorf("begin batch confirmation: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	const loadQuery = `
	SELECT id::text, proposer_subject, confirmer_subject, status, row_count, accepted_count, enrolled_count, failed_count, created_at, confirmed_at
	FROM enrollment_batches WHERE id = $1 FOR UPDATE`
	batch, err := scanBatch(transaction.QueryRow(ctx, loadQuery, id))
	if err != nil {
		return EnrollmentBatch{}, nil, fmt.Errorf("load enrollment batch: %w", err)
	}
	if batch.Status != EnrollmentBatchProposed {
		return EnrollmentBatch{}, nil, fmt.Errorf("enrollment batch is in %q state and cannot be confirmed", batch.Status)
	}
	if err := CanConfirmBatch(batch.ProposerSubject, confirmerSubject); err != nil {
		return EnrollmentBatch{}, nil, err
	}
	if _, err := transaction.Exec(ctx, `UPDATE enrollment_batches SET status = 'confirmed', confirmer_subject = $2, confirmed_at = now() WHERE id = $1`, id, confirmerSubject); err != nil {
		return EnrollmentBatch{}, nil, fmt.Errorf("confirm enrollment batch: %w", err)
	}
	rows, err := transaction.Query(ctx, `SELECT row_index, persona, contact_channel, contact_reference, first_name, last_name, email FROM enrollment_batch_rows WHERE batch_id = $1 AND status = 'accepted' ORDER BY row_index`, id)
	if err != nil {
		return EnrollmentBatch{}, nil, fmt.Errorf("load accepted batch rows: %w", err)
	}
	type acceptedRow struct {
		index int
		input EnrollmentSubmitInput
	}
	var acceptedRows []acceptedRow
	for rows.Next() {
		var row acceptedRow
		if err := rows.Scan(&row.index, &row.input.Persona, &row.input.ContactChannel, &row.input.ContactReference, &row.input.FirstName, &row.input.LastName, &row.input.Email); err != nil {
			rows.Close()
			return EnrollmentBatch{}, nil, fmt.Errorf("scan accepted batch row: %w", err)
		}
		acceptedRows = append(acceptedRows, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return EnrollmentBatch{}, nil, fmt.Errorf("iterate accepted batch rows: %w", err)
	}
	records := make([]EnrollmentBatchRow, 0, len(acceptedRows))
	enrolled, failed := 0, 0
	for _, row := range acceptedRows {
		if _, err := transaction.Exec(ctx, `SAVEPOINT enrollment_row`); err != nil {
			return EnrollmentBatch{}, nil, fmt.Errorf("open batch row savepoint: %w", err)
		}
		var requestID string
		const enrollQuery = `
		INSERT INTO onboarding_requests (organization_id, email, first_name, last_name, requested_roles, requester_subject, persona, contact_channel, contact_reference, status)
		VALUES ($1, $2, $3, $4, '{}', $5, $6, $7, $8, 'pending_verification')
		RETURNING id::text`
		err := transaction.QueryRow(ctx, enrollQuery,
			organizationID, row.input.Email, row.input.FirstName, row.input.LastName, batch.ProposerSubject,
			row.input.Persona, row.input.ContactChannel, row.input.ContactReference,
		).Scan(&requestID)
		if err != nil {
			if _, rollbackErr := transaction.Exec(ctx, `ROLLBACK TO SAVEPOINT enrollment_row`); rollbackErr != nil {
				return EnrollmentBatch{}, nil, fmt.Errorf("roll back failed batch row %d: %w", row.index, rollbackErr)
			}
			message := truncateBatchError(err.Error())
			if _, err := transaction.Exec(ctx, `UPDATE enrollment_batch_rows SET status = 'failed', error = $3 WHERE batch_id = $1 AND row_index = $2`, id, row.index, message); err != nil {
				return EnrollmentBatch{}, nil, fmt.Errorf("record failed batch row %d: %w", row.index, err)
			}
			records = append(records, EnrollmentBatchRow{RowIndex: row.index, Status: BatchRowFailed, Error: message})
			failed++
			continue
		}
		if _, err := transaction.Exec(ctx, `UPDATE enrollment_batch_rows SET status = 'enrolled', request_id = $3 WHERE batch_id = $1 AND row_index = $2`, id, row.index, requestID); err != nil {
			return EnrollmentBatch{}, nil, fmt.Errorf("record enrolled batch row %d: %w", row.index, err)
		}
		records = append(records, EnrollmentBatchRow{RowIndex: row.index, Status: BatchRowEnrolled, RequestID: &requestID})
		enrolled++
	}
	if _, err := transaction.Exec(ctx, `UPDATE enrollment_batches SET enrolled_count = $2, failed_count = $3 WHERE id = $1`, id, enrolled, failed); err != nil {
		return EnrollmentBatch{}, nil, fmt.Errorf("record batch enrollment counts: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return EnrollmentBatch{}, nil, fmt.Errorf("commit batch confirmation: %w", err)
	}
	batch.Status = EnrollmentBatchConfirmed
	batch.ConfirmerSubject = confirmerSubject
	batch.EnrolledCount = enrolled
	batch.FailedCount = failed
	now := time.Now().UTC()
	batch.ConfirmedAt = &now
	return batch, records, nil
}

func scanBatch(row pgx.Row) (EnrollmentBatch, error) {
	var batch EnrollmentBatch
	if err := row.Scan(
		&batch.ID,
		&batch.ProposerSubject,
		&batch.ConfirmerSubject,
		&batch.Status,
		&batch.RowCount,
		&batch.AcceptedCount,
		&batch.EnrolledCount,
		&batch.FailedCount,
		&batch.CreatedAt,
		&batch.ConfirmedAt,
	); err != nil {
		return EnrollmentBatch{}, err
	}
	return batch, nil
}

func truncateBatchError(message string) string {
	const limit = 1024
	if len(message) <= limit {
		return message
	}
	return message[:limit]
}
