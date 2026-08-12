package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (store *Store) Close() {
	store.pool.Close()
}

func (store *Store) Create(ctx context.Context, input SubmitInput, requesterSubject string) (OnboardingRequest, error) {
	const query = `
INSERT INTO onboarding_requests (organization_id, email, first_name, last_name, requested_roles, requester_subject)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id::text, organization_id, email, first_name, last_name, requested_roles, requester_subject, status, created_at, updated_at`
	return scanRequest(store.pool.QueryRow(ctx, query, input.OrganizationID, input.Email, input.FirstName, input.LastName, input.RequestedRoles, requesterSubject))
}

func (store *Store) GetForUpdate(ctx context.Context, transaction pgx.Tx, id string) (OnboardingRequest, error) {
	const query = `
SELECT id::text, organization_id, email, first_name, last_name, requested_roles, requester_subject, status, created_at, updated_at
FROM onboarding_requests WHERE id = $1 FOR UPDATE`
	return scanRequest(transaction.QueryRow(ctx, query, id))
}

func (store *Store) Decide(ctx context.Context, id, approverSubject, decision, reason string) (OnboardingRequest, error) {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return OnboardingRequest{}, fmt.Errorf("begin decision transaction: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	request, err := store.GetForUpdate(ctx, transaction, id)
	if err != nil {
		return OnboardingRequest{}, fmt.Errorf("load onboarding request: %w", err)
	}
	if request.Status != StatusSubmitted {
		return OnboardingRequest{}, fmt.Errorf("request is in %q state and cannot be decided", request.Status)
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
UPDATE onboarding_requests
SET status = 'provisioning'
WHERE id = $1 AND status = 'approved'
RETURNING id::text, organization_id, email, first_name, last_name, requested_roles, requester_subject, status, created_at, updated_at`
	request, err := scanRequest(store.pool.QueryRow(ctx, query, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OnboardingRequest{}, errors.New("onboarding request is not approved for provisioning")
		}
		return OnboardingRequest{}, fmt.Errorf("claim onboarding provisioning: %w", err)
	}
	return request, nil
}

func (store *Store) ClaimActivation(ctx context.Context, id string) (OnboardingRequest, error) {
	const query = `
UPDATE onboarding_requests
SET status = 'activating'
WHERE id = $1 AND status = 'invited'
RETURNING id::text, organization_id, email, first_name, last_name, requested_roles, requester_subject, status, created_at, updated_at`
	request, err := scanRequest(store.pool.QueryRow(ctx, query, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OnboardingRequest{}, errors.New("onboarding request is not invited for activation")
		}
		return OnboardingRequest{}, fmt.Errorf("claim onboarding activation: %w", err)
	}
	return request, nil
}

func (store *Store) RecordActivationResult(ctx context.Context, id, actorSubject string, success bool, reason string) error {
	status := StatusActivationFailed
	decision := "activation_failed"
	if success {
		status = StatusActive
		decision = "active"
	}
	command, err := store.pool.Exec(ctx, `UPDATE onboarding_requests SET status = $2 WHERE id = $1 AND status = 'activating'`, id, status)
	if err != nil {
		return fmt.Errorf("update activation status: %w", err)
	}
	if command.RowsAffected() != 1 {
		return errors.New("onboarding request is not in activating state")
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO onboarding_decisions (request_id, decision, actor_subject, reason) VALUES ($1, $2, $3, $4)`, id, decision, actorSubject, reason); err != nil {
		return fmt.Errorf("write activation decision: %w", err)
	}
	return nil
}

func (store *Store) RecordProvisioningResult(ctx context.Context, id, actorSubject string, success bool, reason string) error {
	status := StatusProvisioningFailed
	if success {
		status = StatusInvited
	}
	command, err := store.pool.Exec(ctx, `UPDATE onboarding_requests SET status = $2 WHERE id = $1 AND status = 'provisioning'`, id, status)
	if err != nil {
		return fmt.Errorf("update provisioning status: %w", err)
	}
	if command.RowsAffected() != 1 {
		return errors.New("onboarding request is not in approved state")
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO onboarding_decisions (request_id, decision, actor_subject, reason) VALUES ($1, $2, $3, $4)`, id, status, actorSubject, reason); err != nil {
		return fmt.Errorf("write provisioning decision: %w", err)
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
		&request.CreatedAt,
		&request.UpdatedAt,
	); err != nil {
		return OnboardingRequest{}, err
	}
	return request, nil
}
