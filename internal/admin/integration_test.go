package admin

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/munisp/blueeconomy-administration-service/internal/provenance"
)

// These tests run against a real PostgreSQL when ADMIN_TEST_POSTGRES_DSN is
// set (the repo's database-gated convention); they are skipped otherwise.
// The enrollment lifecycle, maker/checker refusal and the public-endpoint
// rate limit are all transactional/UNIQUE-semantics behaviour — there is no
// honest in-memory substitute. Only the Keycloak administration seam (an
// external identity system) is out of scope here; the lifecycle is driven
// through the store exactly as the HTTP handlers drive it.

// integrationStore opens a store against a freshly rebuilt schema with all
// shipped migrations applied, in order.
func integrationStore(t *testing.T) *Store {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("ADMIN_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("ADMIN_TEST_POSTGRES_DSN is not set; skipping database-gated enrollment tests")
	}
	ctx := context.Background()
	store, err := NewStore(ctx, dsn)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(store.Close)
	if _, err := store.pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset test schema: %v", err)
	}
	migrationDir := filepath.Join("..", "..", "db", "migrations")
	entries, err := filepath.Glob(filepath.Join(migrationDir, "*.sql"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("find migrations: %v", err)
	}
	sort.Strings(entries)
	for _, entry := range entries {
		migration, err := os.ReadFile(entry)
		if err != nil {
			t.Fatalf("read migration %s: %v", entry, err)
		}
		// Apply statements individually (psql autocommit semantics, the
		// repo's own integration/run-local.sh convention): the migrations
		// ALTER enum types and use the new values in later statements, which
		// a single multi-statement Exec would reject (55P04).
		for index, statement := range splitSQLStatements(string(migration)) {
			if _, err := store.pool.Exec(ctx, statement); err != nil {
				t.Fatalf("apply migration %s statement %d: %v", entry, index+1, err)
			}
		}
	}
	return store
}

// splitSQLStatements splits a migration into statements on top-level
// semicolons, honouring single-quoted strings, line/block comments and
// dollar-quoted bodies (the trigger functions in the migrations).
func splitSQLStatements(script string) []string {
	var statements []string
	start := 0
	index := 0
	for index < len(script) {
		switch {
		case script[index] == '\'':
			index++
			for index < len(script) {
				if script[index] == '\'' {
					if index+1 < len(script) && script[index+1] == '\'' {
						index += 2
						continue
					}
					break
				}
				index++
			}
			index++
		case strings.HasPrefix(script[index:], "--"):
			for index < len(script) && script[index] != '\n' {
				index++
			}
		case strings.HasPrefix(script[index:], "/*"):
			end := strings.Index(script[index+2:], "*/")
			if end < 0 {
				index = len(script)
			} else {
				index += 2 + end + 2
			}
		case script[index] == '$':
			// Dollar-quoted string: $tag$ ... $tag$
			rest := script[index:]
			tagEnd := strings.Index(rest[1:], "$")
			if tagEnd < 0 {
				index++
				continue
			}
			tag := rest[:tagEnd+2]
			body := strings.Index(rest[len(tag):], tag)
			if body < 0 {
				index = len(script)
			} else {
				index += len(tag) + body + len(tag)
			}
		case script[index] == ';':
			if statement := strings.TrimSpace(script[start:index]); statement != "" {
				statements = append(statements, statement)
			}
			index++
			start = index
		default:
			index++
		}
	}
	if statement := strings.TrimSpace(script[start:]); statement != "" {
		statements = append(statements, statement)
	}
	return statements
}

func integrationSigner(t *testing.T) *provenance.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate provenance key: %v", err)
	}
	signer, err := provenance.NewSigner("integration-key-1", key)
	if err != nil {
		t.Fatalf("build provenance signer: %v", err)
	}
	return signer
}

func (store *Store) countWhere(t *testing.T, query string, args ...any) int {
	t.Helper()
	var count int
	if err := store.pool.QueryRow(context.Background(), query, args...).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return count
}

// driveToActive walks the approved lifecycle: submitted -> approved ->
// provisioning -> invited -> activating -> active, asserting every claim and
// settlement, exactly as the HTTP handlers and reconciler drive it.
func driveToActive(t *testing.T, store *Store, id, actor string) OnboardingRequest {
	t.Helper()
	ctx := context.Background()

	claimed, err := store.ClaimProvisioning(ctx, id)
	if err != nil {
		t.Fatalf("claim provisioning: %v", err)
	}
	if claimed.Status != StatusProvisioning {
		t.Fatalf("provisioning claim left status %s", claimed.Status)
	}
	if err := store.RecordProvisioningResult(ctx, id, actor, true, "keycloak invitation sent"); err != nil {
		t.Fatalf("record provisioning result: %v", err)
	}
	invited, err := store.Get(ctx, id)
	if err != nil || invited.Status != StatusInvited {
		t.Fatalf("after provisioning: status = %s, err = %v", invited.Status, err)
	}

	activating, err := store.ClaimActivation(ctx, id, "keycloak-user-"+id[:8])
	if err != nil {
		t.Fatalf("claim activation: %v", err)
	}
	if activating.Status != StatusActivating {
		t.Fatalf("activation claim left status %s", activating.Status)
	}
	if err := store.RecordActivationResult(ctx, id, actor, true, "role groups assigned"); err != nil {
		t.Fatalf("record activation result: %v", err)
	}
	active, err := store.Get(ctx, id)
	if err != nil || active.Status != StatusActive {
		t.Fatalf("after activation: status = %s, err = %v", active.Status, err)
	}
	return active
}

// GAP (a): the officer-submitted enrollment lifecycle — create -> approve ->
// provision -> activation (role grant) — against the real schema, including
// the maker/checker refusal: the requester can never approve their own
// request, and the refusal leaves the request untouched.
func TestIntegration_EnrollmentLifecycleCreateApproveRoleGrant(t *testing.T) {
	store := integrationStore(t).WithSigner(integrationSigner(t))
	ctx := context.Background()

	created, err := store.Create(ctx, SubmitInput{
		OrganizationID: "tenant-lifecycle-a",
		Email:          "candidate-a@example.invalid",
		FirstName:      "Adaeze", LastName: "Okafor",
		RequestedRoles: []string{"nimasa-officer"},
	}, "requester-1")
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if created.Status != StatusSubmitted {
		t.Fatalf("created status = %s, want submitted", created.Status)
	}

	// Maker/checker: approver == requester is refused, and the refusal is
	// not a state change — the request stays decidable by a real checker.
	if _, err := store.Decide(ctx, created.ID, "requester-1", "approve", "self-approval attempt"); !errors.Is(err, ErrMakerCheckerViolation) {
		t.Fatalf("self-approval: err = %v, want ErrMakerCheckerViolation", err)
	}
	after, err := store.Get(ctx, created.ID)
	if err != nil || after.Status != StatusSubmitted {
		t.Fatalf("self-approval attempt changed state: %s (err %v)", after.Status, err)
	}
	if got := store.countWhere(t, `SELECT count(*) FROM onboarding_decisions WHERE request_id=$1`, created.ID); got != 0 {
		t.Fatalf("refused self-approval wrote %d decision rows", got)
	}

	decided, err := store.Decide(ctx, created.ID, "approver-1", "approve", "vetting complete")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if decided.Status != StatusApproved {
		t.Fatalf("decided status = %s, want approved", decided.Status)
	}
	// A second decision on the decided request is refused.
	if _, err := store.Decide(ctx, created.ID, "approver-2", "approve", "duplicate decision"); err == nil {
		t.Fatal("duplicate decision on an approved request must fail")
	}

	active := driveToActive(t, store, created.ID, "service-activator")

	// The role grant is only complete with its provenance-signed activation
	// notice in the outbox and the notification marked pending — exactly one.
	if got := store.countWhere(t,
		`SELECT count(*) FROM onboarding_outbox_events WHERE request_id=$1 AND event_type LIKE '%activat%'`, created.ID); got != 1 {
		t.Fatalf("activation outbox events = %d, want exactly 1", got)
	}
	var signature string
	if err := store.pool.QueryRow(ctx,
		`SELECT provenance_signature FROM onboarding_outbox_events WHERE request_id=$1`, created.ID).Scan(&signature); err != nil {
		t.Fatalf("load activation signature: %v", err)
	}
	if signature == "" {
		t.Fatal("activation notice must carry a provenance signature")
	}
	if active.NotificationStatus != NotificationPending {
		t.Fatalf("notification status = %s, want pending", active.NotificationStatus)
	}
	if got := store.countWhere(t,
		`SELECT count(*) FROM onboarding_external_operations WHERE request_id=$1 AND status='succeeded'`, created.ID); got != 2 {
		t.Fatalf("succeeded external operations = %d, want 2 (provision + activate)", got)
	}
}

// GAP (a), self-service path: a public enrollment request can only reach a
// decision after an officer completes identity proofing, and then the normal
// approve -> provision -> activation lifecycle applies. Regression: the
// store decision path must honour the persona-aware CanDecide gate
// (identity_verified), not dead-end KYC-complete enrollments.
func TestIntegration_SelfServiceEnrollmentKYCBeforeDecision(t *testing.T) {
	store := integrationStore(t).WithSigner(integrationSigner(t))
	ctx := context.Background()

	created, err := store.CreateEnrollment(ctx, "tenant-lifecycle-b", EnrollmentSubmitInput{
		Persona: "fisher", ContactChannel: "sms", ContactReference: "+2348012345678",
		FirstName: "Bassey", LastName: "Etim",
	}, SelfServiceRequesterSubject)
	if err != nil {
		t.Fatalf("create enrollment: %v", err)
	}
	if created.Status != StatusPendingVerification {
		t.Fatalf("enrollment status = %s, want pending_verification", created.Status)
	}

	// No decision is possible before identity proofing completes.
	if _, err := store.Decide(ctx, created.ID, "approver-1", "approve", "skip-kyc attempt"); err == nil {
		t.Fatal("decision before KYC must be refused")
	}

	if _, err := store.StartIdentityReview(ctx, created.ID, "officer-1"); err != nil {
		t.Fatalf("start identity review: %v", err)
	}
	if _, err := store.RecordIdentityVerification(ctx, created.ID, "officer-1", IdentityVerificationInput{
		Outcome:                 string(StatusIdentityVerified),
		DocumentType:            "national-id",
		DocumentReferenceSHA256: "sha256:" + strings.Repeat("a", 64),
		Reason:                  "NIN verified at desk",
	}); err != nil {
		t.Fatalf("record identity verification: %v", err)
	}
	verified, err := store.Get(ctx, created.ID)
	if err != nil || verified.Status != StatusIdentityVerified {
		t.Fatalf("after KYC: status = %s, err = %v", verified.Status, err)
	}
	if got := store.countWhere(t, `SELECT count(*) FROM onboarding_kyc_reviews WHERE request_id=$1`, created.ID); got != 1 {
		t.Fatalf("kyc review rows = %d, want 1", got)
	}

	// KYC-complete: a checker (never the fixed self-service requester)
	// approves, and the standard lifecycle completes to the role grant.
	decided, err := store.Decide(ctx, created.ID, "approver-1", "approve", "identity verified")
	if err != nil {
		t.Fatalf("approve identity-verified enrollment: %v", err)
	}
	if decided.Status != StatusApproved {
		t.Fatalf("decided status = %s, want approved", decided.Status)
	}
	driveToActive(t, store, created.ID, "service-activator")
	if got := store.countWhere(t,
		`SELECT count(*) FROM onboarding_outbox_events WHERE request_id=$1`, created.ID); got != 1 {
		t.Fatalf("activation outbox events = %d, want exactly 1", got)
	}
}

// GAP (b): the deliberately public POST /v1/enrollment/requests is guarded
// by the strict fixed-window rate limit backed by the real
// enrollment_rate_limits table: the window admits exactly the configured
// number of requests per IP, the overflow is a 429 that writes no enrollment
// row, a distinct IP gets its own window, and a disabled limit fails closed
// with 503 (never an open endpoint).
func TestIntegration_PublicEnrollmentRateLimitAbuseGuard(t *testing.T) {
	store := integrationStore(t)
	service := &HTTPService{
		store:               store,
		organizationID:      "tenant-public-guard",
		authenticator:       stubAuthenticator{err: errors.New("no credential")},
		rateLimiter:         store,
		enrollmentRateLimit: 3,
		tenantLookup:        store,
	}
	handler := service.Handler()

	body := func(suffix string) string {
		return `{"persona":"fisher","contact_channel":"sms","contact_reference":"+2348012345` + suffix + `","first_name":"Bassey","last_name":"Etim"}`
	}
	post := func(remoteAddr, payload string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/enrollment/requests", strings.NewReader(payload))
		request.RemoteAddr = remoteAddr
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}

	// The window admits exactly three requests from this IP. (Contact
	// references vary per request: the enrollment dedup index would
	// otherwise refuse duplicates, which is not what is under test here.)
	for attempt := 1; attempt <= 3; attempt++ {
		if response := post("203.0.113.10:4433", body(fmt.Sprintf("%03d", attempt))); response.Code != http.StatusCreated {
			t.Fatalf("attempt %d: status = %d, want 201 (body %s)", attempt, response.Code, response.Body.String())
		}
	}
	// The fourth is the abuse guard: 429, and no enrollment row is written.
	if response := post("203.0.113.10:4433", body("004")); response.Code != http.StatusTooManyRequests {
		t.Fatalf("overflow: status = %d, want 429", response.Code)
	}
	if got := store.countWhere(t, `SELECT count(*) FROM onboarding_requests WHERE organization_id='tenant-public-guard'`); got != 3 {
		t.Fatalf("enrollment rows = %d, want exactly 3 (429 must not persist)", got)
	}
	var windowCount int
	if err := store.pool.QueryRow(context.Background(),
		`SELECT request_count FROM enrollment_rate_limits WHERE bucket_key='ip:203.0.113.10'`).Scan(&windowCount); err != nil {
		t.Fatalf("load rate-limit window: %v", err)
	}
	if windowCount != 4 {
		t.Fatalf("window count = %d, want 4 claims (3 admitted + 1 denied)", windowCount)
	}

	// A distinct source IP gets its own window.
	if response := post("198.51.100.7:4433", body("005")); response.Code != http.StatusCreated {
		t.Fatalf("distinct IP: status = %d, want 201", response.Code)
	}

	// Fail closed: with the limit disabled the public endpoint refuses
	// rather than admitting unbounded anonymous enrollment.
	disabled := &HTTPService{
		store:               store,
		organizationID:      "tenant-public-guard",
		authenticator:       stubAuthenticator{err: errors.New("no credential")},
		rateLimiter:         store,
		enrollmentRateLimit: 0,
		tenantLookup:        store,
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/enrollment/requests", strings.NewReader(body("006")))
	request.RemoteAddr = "192.0.2.1:4433"
	disabled.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled limit: status = %d, want 503 (fail closed)", recorder.Code)
	}
}
