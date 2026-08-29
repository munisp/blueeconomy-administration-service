package admin

import (
	"github.com/munisp/blueeconomy-administration-service/internal/provenance"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/munisp/blueeconomy-administration-service/internal/telemetry"
)

type Store struct {
	pool   *pgxpool.Pool
	signer *provenance.Signer
}

// WithSigner attaches the provenance signer used to seal every emitted
// onboarding outbox envelope. Emission paths fail closed when no signer is
// attached.
func (store *Store) WithSigner(signer *provenance.Signer) *Store {
	store.signer = signer
	return store
}

func NewStore(ctx context.Context, dsn string) (*Store, error) {
	// otelpgx query spans (OTEL_DESIGN §2 Postgres row); with telemetry
	// disabled the tracer runs over a noop provider and pool semantics are
	// unchanged.
	pool, err := telemetry.Default().NewPGXPool(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	return &Store{pool: pool}, nil
}

// OnboardingRequestTenant resolves the owning organization (tenant) of one
// onboarding request for policy evaluation. Unknown ids return ErrNotFound.
func (store *Store) OnboardingRequestTenant(ctx context.Context, id string) (string, error) {
	var organizationID string
	err := store.pool.QueryRow(ctx, `SELECT organization_id FROM onboarding_requests WHERE id = $1`, id).Scan(&organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("load onboarding request tenant: %w", err)
	}
	return organizationID, nil
}

func (store *Store) Close() {
	store.pool.Close()
}

func (store *Store) StartReconciler(ctx context.Context, actorSubject string) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := store.ReapExpiredExternalOperations(ctx, actorSubject); err != nil {
					log.Printf("external operation reconciliation: %v", err)
				}
			}
		}
	}()
}

func (store *Store) Create(ctx context.Context, input SubmitInput, requesterSubject string) (OnboardingRequest, error) {
	const query = `
	INSERT INTO onboarding_requests (organization_id, email, first_name, last_name, requested_roles, requester_subject)
	VALUES ($1, $2, $3, $4, $5, $6)
	RETURNING id::text, organization_id, email, first_name, last_name, requested_roles, requester_subject, status, persona, contact_channel, contact_reference, notification_status, created_at, updated_at`
	return scanRequest(store.pool.QueryRow(ctx, query, input.OrganizationID, input.Email, input.FirstName, input.LastName, input.RequestedRoles, requesterSubject))
}

// Get loads one onboarding request by id without claiming a state
// transition. Missing ids return ErrNotFound.
func (store *Store) Get(ctx context.Context, id string) (OnboardingRequest, error) {
	const query = `
	SELECT id::text, organization_id, email, first_name, last_name, requested_roles, requester_subject, status, persona, contact_channel, contact_reference, notification_status, created_at, updated_at
	FROM onboarding_requests WHERE id = $1`
	request, err := scanRequest(store.pool.QueryRow(ctx, query, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return OnboardingRequest{}, ErrNotFound
	}
	if err != nil {
		return OnboardingRequest{}, fmt.Errorf("load onboarding request: %w", err)
	}
	return request, nil
}

func (store *Store) GetForUpdate(ctx context.Context, transaction pgx.Tx, id string) (OnboardingRequest, error) {
	const query = `
	SELECT id::text, organization_id, email, first_name, last_name, requested_roles, requester_subject, status, persona, contact_channel, contact_reference, notification_status, created_at, updated_at
	FROM onboarding_requests WHERE id = $1 FOR UPDATE`
	return scanRequest(transaction.QueryRow(ctx, query, id))
}

// Decide runs the enrollment Decide gate under an admin Decision action
// span (OTEL_DESIGN §2): the gate is an audit-critical privileged action, so
// every decision attempt — approved, rejected or refused by the gate — is
// traced with its outcome; subject identity stays off the span.
func (store *Store) Decide(ctx context.Context, id, approverSubject, decision, reason string) (OnboardingRequest, error) {
	ctx, span := telemetry.Default().StartSpan(ctx, "admin.enrollment.decide", trace.SpanKindInternal,
		attribute.String("admin.decision", decision))
	defer span.End()
	decided, err := store.decide(ctx, id, approverSubject, decision, reason)
	if err != nil {
		span.RecordError(err)
		span.SetAttributes(attribute.String("admin.decision.outcome", "refused"))
		return OnboardingRequest{}, err
	}
	span.SetAttributes(attribute.String("admin.decision.outcome", string(decided.Status)))
	return decided, nil
}

func (store *Store) decide(ctx context.Context, id, approverSubject, decision, reason string) (OnboardingRequest, error) {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return OnboardingRequest{}, fmt.Errorf("begin decision transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	request, err := store.GetForUpdate(ctx, transaction, id)
	if err != nil {
		return OnboardingRequest{}, fmt.Errorf("load onboarding request: %w", err)
	}
	// The decision gate is persona-aware (model.CanDecide): officer-submitted
	// requests are decided from submitted; self-service enrollment requests
	// only after an officer completed identity proofing (identity_verified).
	// Without this gate a KYC-complete enrollment could never be decided and
	// the public journey dead-ended.
	if err := request.CanDecide(); err != nil {
		return OnboardingRequest{}, err
	}
	if err := CanApprove(request.RequesterSubject, approverSubject); err != nil {
		return OnboardingRequest{}, err
	}
	status := StatusRejected
	if decision == "approve" {
		status = StatusApproved
	} else if decision != "reject" {
		return OnboardingRequest{}, errors.New("decision must be approve or reject")
	}
	if _, err := transaction.Exec(ctx, `UPDATE onboarding_requests SET status = $2 WHERE id = $1`, id, status); err != nil {
		return OnboardingRequest{}, fmt.Errorf("update onboarding status: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO onboarding_decisions (request_id, decision, actor_subject, reason) VALUES ($1, $2, $3, $4)`, id, status, approverSubject, reason); err != nil {
		return OnboardingRequest{}, fmt.Errorf("write onboarding decision: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return OnboardingRequest{}, fmt.Errorf("commit onboarding decision: %w", err)
	}
	request.Status = status
	request.UpdatedAt = time.Now().UTC()
	return request, nil
}

func (store *Store) ClaimProvisioning(ctx context.Context, id string) (OnboardingRequest, error) {
	const query = `
	WITH claimed AS (
		UPDATE onboarding_requests
		SET status = 'provisioning'
		WHERE id = $1 AND status = 'approved'
		RETURNING id, organization_id, email, first_name, last_name, requested_roles, requester_subject, status, persona, contact_channel, contact_reference, notification_status, created_at, updated_at
	), operation AS (
		INSERT INTO onboarding_external_operations (request_id, operation_kind, status, lease_until)
		SELECT id, 'provision', 'running', now() + interval '60 seconds' FROM claimed
		RETURNING request_id
	)
	SELECT claimed.id::text, claimed.organization_id, claimed.email, claimed.first_name, claimed.last_name,
	       claimed.requested_roles, claimed.requester_subject, claimed.status, claimed.persona,
	       claimed.contact_channel, claimed.contact_reference, claimed.notification_status, claimed.created_at, claimed.updated_at
	FROM claimed JOIN operation ON operation.request_id = claimed.id`
	request, err := scanRequest(store.pool.QueryRow(ctx, query, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OnboardingRequest{}, errors.New("onboarding request is not approved for provisioning")
		}
		return OnboardingRequest{}, fmt.Errorf("claim onboarding provisioning: %w", err)
	}
	return request, nil
}

// ClaimActivation atomically moves an invited request into the activating
// state and records the activation operation. keycloakUserID must be the
// server-resolved identity of the vetted candidate e-mail (never client
// input); it is stored on the operation as an immutable identity field.
func (store *Store) ClaimActivation(ctx context.Context, id, keycloakUserID string) (OnboardingRequest, error) {
	if keycloakUserID == "" {
		return OnboardingRequest{}, errors.New("Keycloak user ID is required for activation")
	}
	const query = `
	WITH claimed AS (
		UPDATE onboarding_requests
		SET status = 'activating'
		WHERE id = $1 AND status = 'invited'
		RETURNING id, organization_id, email, first_name, last_name, requested_roles, requester_subject, status, persona, contact_channel, contact_reference, notification_status, created_at, updated_at
	), operation AS (
		INSERT INTO onboarding_external_operations (request_id, operation_kind, status, keycloak_user_id, lease_until)
		SELECT id, 'activate', 'running', $2, now() + interval '60 seconds' FROM claimed
		RETURNING request_id
	)
	SELECT claimed.id::text, claimed.organization_id, claimed.email, claimed.first_name, claimed.last_name,
	       claimed.requested_roles, claimed.requester_subject, claimed.status, claimed.persona,
	       claimed.contact_channel, claimed.contact_reference, claimed.notification_status, claimed.created_at, claimed.updated_at
	FROM claimed JOIN operation ON operation.request_id = claimed.id`
	request, err := scanRequest(store.pool.QueryRow(ctx, query, id, keycloakUserID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OnboardingRequest{}, errors.New("onboarding request is not invited for activation")
		}
		return OnboardingRequest{}, fmt.Errorf("claim onboarding activation: %w", err)
	}
	return request, nil
}

func (store *Store) RecordActivationResult(ctx context.Context, id, actorSubject string, success bool, reason string) error {
	if success {
		return store.recordExternalResult(ctx, id, actorSubject, "activate", StatusActivating, StatusActive, "active", reason, "succeeded")
	}
	return store.recordExternalResult(ctx, id, actorSubject, "activate", StatusActivating, StatusActivationAmbiguous, "activation_ambiguous", reason, "ambiguous")
}

func (store *Store) RecordProvisioningResult(ctx context.Context, id, actorSubject string, success bool, reason string) error {
	if success {
		return store.recordExternalResult(ctx, id, actorSubject, "provision", StatusProvisioning, StatusInvited, "invited", reason, "succeeded")
	}
	return store.recordExternalResult(ctx, id, actorSubject, "provision", StatusProvisioning, StatusProvisioningAmbiguous, "provisioning_ambiguous", reason, "ambiguous")
}

func (store *Store) recordExternalResult(ctx context.Context, id, actorSubject, operationKind string, expectedStatus, nextStatus RequestStatus, decision, reason, operationStatus string) error {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin external-result transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	command, err := transaction.Exec(ctx, `UPDATE onboarding_external_operations SET status = $3, last_error = $4, lease_until = now() WHERE request_id = $1 AND operation_kind = $2 AND status = 'running'`, id, operationKind, operationStatus, reason)
	if err != nil {
		return fmt.Errorf("update external-operation result: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("external operation %s for onboarding request is not running", operationKind)
	}
	command, err = transaction.Exec(ctx, `UPDATE onboarding_requests SET status = $3 WHERE id = $1 AND status = $2`, id, expectedStatus, nextStatus)
	if err != nil {
		return fmt.Errorf("update external-result status: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("onboarding request is not in %q state", expectedStatus)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO onboarding_decisions (request_id, decision, actor_subject, reason) VALUES ($1, $2, $3, $4)`, id, decision, actorSubject, reason); err != nil {
		return fmt.Errorf("write external-result decision: %w", err)
	}
	if operationKind == "activate" && nextStatus == StatusActive {
		if err := insertActivationNotice(ctx, transaction, store.signer, id, actorSubject); err != nil {
			return fmt.Errorf("record activation notice: %w", err)
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit external-result transition: %w", err)
	}
	return nil
}

func (store *Store) ReapExpiredExternalOperations(ctx context.Context, actorSubject string) error {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin external-operation reconciliation: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	rows, err := transaction.Query(ctx, `SELECT id::text, request_id::text, operation_kind::text FROM onboarding_external_operations WHERE status = 'running' AND lease_until < now() FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return fmt.Errorf("find expired external operations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var operationID, requestID, operationKind string
		if err := rows.Scan(&operationID, &requestID, &operationKind); err != nil {
			return fmt.Errorf("scan expired external operation: %w", err)
		}
		requestStatus := StatusProvisioningAmbiguous
		decision := "provisioning_ambiguous"
		if operationKind == "activate" {
			requestStatus = StatusActivationAmbiguous
			decision = "activation_ambiguous"
		}
		if _, err := transaction.Exec(ctx, `UPDATE onboarding_external_operations SET status = 'ambiguous', last_error = 'operation lease expired before a durable result was recorded', lease_until = now() WHERE id = $1`, operationID); err != nil {
			return fmt.Errorf("mark expired external operation ambiguous: %w", err)
		}
		if _, err := transaction.Exec(ctx, `UPDATE onboarding_requests SET status = $2 WHERE id = $1 AND status IN ('provisioning', 'activating')`, requestID, requestStatus); err != nil {
			return fmt.Errorf("mark onboarding request ambiguous: %w", err)
		}
		if _, err := transaction.Exec(ctx, `INSERT INTO onboarding_decisions (request_id, decision, actor_subject, reason) VALUES ($1, $2, $3, $4)`, requestID, decision, actorSubject, "external operation lease expired; manual reconciliation required"); err != nil {
			return fmt.Errorf("record ambiguous external operation: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate expired external operations: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit external-operation reconciliation: %w", err)
	}
	return nil
}

func scanRequest(row pgx.Row) (OnboardingRequest, error) {
	var request OnboardingRequest
	if err := row.Scan(
		&request.ID,
		&request.OrganizationID,
		&request.Email,
		&request.FirstName,
		&request.LastName,
		&request.RequestedRoles,
		&request.RequesterSubject,
		&request.Status,
		&request.Persona,
		&request.ContactChannel,
		&request.ContactReference,
		&request.NotificationStatus,
		&request.CreatedAt,
		&request.UpdatedAt,
	); err != nil {
		return OnboardingRequest{}, err
	}
	return request, nil
}
