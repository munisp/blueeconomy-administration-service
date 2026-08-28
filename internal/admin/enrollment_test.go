package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func validEnrollmentInput() EnrollmentSubmitInput {
	return EnrollmentSubmitInput{
		Persona:          "fisher",
		ContactChannel:   "sms",
		ContactReference: "+2348012345678",
		FirstName:        "Adaeze",
		LastName:         "Okafor",
	}
}

// TestEnrollmentSubmitValidation proves the self-service contract accepts
// every approved persona and channel and rejects anything outside the
// catalogues before storage.
func TestEnrollmentSubmitValidation(t *testing.T) {
	for _, persona := range []string{"trucker", "ferry-passenger", "operator", "fisher", "seafarer-trainee", "beneficiary", "exporter", "processor", "fleet-operator"} {
		input := validEnrollmentInput()
		input.Persona = persona
		if err := input.Validate(); err != nil {
			t.Errorf("approved persona %q was rejected: %v", persona, err)
		}
	}
	for _, channel := range []string{"sms", "ussd", "app"} {
		input := validEnrollmentInput()
		input.ContactChannel = channel
		if channel == "app" {
			input.ContactReference = "stakeholder-app.device-1"
		}
		if err := input.Validate(); err != nil {
			t.Errorf("approved channel %q was rejected: %v", channel, err)
		}
	}
	input := validEnrollmentInput()
	input.ContactChannel = "email"
	input.ContactReference = "fisher@example.invalid"
	input.Email = "fisher@example.invalid"
	if err := input.Validate(); err != nil {
		t.Fatalf("email channel with matching email was rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*EnrollmentSubmitInput)
	}{
		{"unapproved persona", func(input *EnrollmentSubmitInput) { input.Persona = "stowaway" }},
		{"unapproved channel", func(input *EnrollmentSubmitInput) { input.ContactChannel = "whatsapp" }},
		{"empty contact reference", func(input *EnrollmentSubmitInput) { input.ContactReference = "" }},
		{"non-numeric sms reference", func(input *EnrollmentSubmitInput) { input.ContactReference = "+23480CALLME" }},
		{"oversized contact reference", func(input *EnrollmentSubmitInput) { input.ContactReference = "+" + strings.Repeat("1", 320) }},
		{"empty first name", func(input *EnrollmentSubmitInput) { input.FirstName = "" }},
		{"oversized last name", func(input *EnrollmentSubmitInput) { input.LastName = strings.Repeat("a", 256) }},
		{"email channel mismatch", func(input *EnrollmentSubmitInput) {
			input.ContactChannel = "email"
			input.ContactReference = "fisher@example.invalid"
			input.Email = "other@example.invalid"
		}},
		{"invalid optional email", func(input *EnrollmentSubmitInput) { input.Email = "not-an-email" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input := validEnrollmentInput()
			testCase.mutate(&input)
			if err := input.Normalize().Validate(); err == nil {
				t.Fatal("expected invalid enrollment input to be rejected")
			}
		})
	}
}

// TestEnrollmentNormalizeCanonicalizes mirrors the onboarding normalization
// contract for the self-service input.
func TestEnrollmentNormalizeCanonicalizes(t *testing.T) {
	input := EnrollmentSubmitInput{
		Persona:          " fisher ",
		ContactChannel:   " sms ",
		ContactReference: " +2348012345678 ",
		FirstName:        " Adaeze ",
		LastName:         " Okafor ",
	}.Normalize()
	if input.Persona != "fisher" || input.ContactChannel != "sms" || input.ContactReference != "+2348012345678" {
		t.Fatalf("enrollment fields were not canonicalized: %#v", input)
	}
	if err := input.Validate(); err != nil {
		t.Fatalf("canonical enrollment did not validate: %v", err)
	}
}

type stubRateLimiter struct {
	allowed bool
	err     error
	calls   int
}

func (stub *stubRateLimiter) AllowEnrollmentRequest(context.Context, string, time.Time, int) (bool, error) {
	stub.calls++
	return stub.allowed, stub.err
}

func newEnrollmentStubService(limiter *stubRateLimiter, limit int) *HTTPService {
	var rateLimiter enrollmentRateLimiter
	if limiter != nil {
		rateLimiter = limiter
	}
	return &HTTPService{
		authenticator:       stubAuthenticator{err: errors.New("no credential")},
		rateLimiter:         rateLimiter,
		enrollmentRateLimit: limit,
	}
}

// TestSelfServiceEndpointIsPublicButRateLimited proves the public endpoint
// needs no credential, that a denied window yields 429, and that the rate
// limit is enforced before body validation (junk still consumes the window).
func TestSelfServiceEndpointIsPublicButRateLimited(t *testing.T) {
	limiter := &stubRateLimiter{allowed: false}
	service := newEnrollmentStubService(limiter, 5)
	request := httptest.NewRequest(http.MethodPost, "/v1/enrollment/requests", strings.NewReader(`{}`))
	request.RemoteAddr = "203.0.113.10:4433"
	recorder := httptest.NewRecorder()
	service.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("denied window must be 429, got %d", recorder.Code)
	}
	if limiter.calls != 1 {
		t.Fatalf("rate limiter must run before validation, calls=%d", limiter.calls)
	}

	limiter.allowed = true
	recorder = httptest.NewRecorder()
	service.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/enrollment/requests", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("admitted request must reach validation (400 for empty body), got %d", recorder.Code)
	}
}

// TestSelfServiceRateLimitFailsClosed covers limiter storage errors and a
// missing/disabled limiter configuration: both deny rather than admit.
func TestSelfServiceRateLimitFailsClosed(t *testing.T) {
	limiter := &stubRateLimiter{err: errors.New("postgres unavailable")}
	service := newEnrollmentStubService(limiter, 5)
	recorder := httptest.NewRecorder()
	service.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/enrollment/requests", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("limiter error must fail closed with 503, got %d", recorder.Code)
	}

	for _, service := range []*HTTPService{
		newEnrollmentStubService(nil, 5),
		newEnrollmentStubService(&stubRateLimiter{allowed: true}, 0),
	} {
		recorder := httptest.NewRecorder()
		service.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/enrollment/requests", strings.NewReader(`{}`)))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("unconfigured rate limit must fail closed with 503, got %d", recorder.Code)
		}
	}
}

// TestAllowEnrollmentRequestRejectsNonPositiveLimit proves the store guard
// itself is fail-closed even before any SQL executes.
func TestAllowEnrollmentRequestRejectsNonPositiveLimit(t *testing.T) {
	store := &Store{}
	if _, err := store.AllowEnrollmentRequest(context.Background(), "ip:203.0.113.10", time.Now().UTC(), 0); err == nil {
		t.Fatal("a non-positive limit must be rejected before storage")
	}
}

// TestEnrollmentRateLimitKeyScopesPerSubjectOrIP verifies the window key:
// an authenticated subject wins, otherwise the client IP is used.
func TestEnrollmentRateLimitKeyScopesPerSubjectOrIP(t *testing.T) {
	service := &HTTPService{authenticator: stubAuthenticator{identity: AuthenticatedIdentity{Subject: "subject-9"}}}
	request := httptest.NewRequest(http.MethodPost, "/v1/enrollment/requests", nil)
	request.RemoteAddr = "203.0.113.10:4433"
	if key := service.enrollmentRateLimitKey(request); key != "subject:subject-9" {
		t.Fatalf("expected subject-scoped key, got %q", key)
	}

	service = &HTTPService{authenticator: stubAuthenticator{err: errors.New("no credential")}}
	if key := service.enrollmentRateLimitKey(request); key != "ip:203.0.113.10" {
		t.Fatalf("expected IP-scoped key, got %q", key)
	}
	request.RemoteAddr = "garbage"
	if key := service.enrollmentRateLimitKey(request); key != "ip:unknown" {
		t.Fatalf("unparseable remote address must fall back to a shared deny bucket, got %q", key)
	}
}

// TestSelfServiceRequestCanNeverReachDecisionWithoutKYC is the
// no-privilege-escalation gate: a self-service request in any pre-verification
// state is refused a decision, and only identity_verified unlocks one.
func TestSelfServiceRequestCanNeverReachDecisionWithoutKYC(t *testing.T) {
	selfService := OnboardingRequest{Persona: "fisher", RequesterSubject: SelfServiceRequesterSubject}
	for _, status := range []RequestStatus{
		StatusPendingVerification, StatusIdentityReview, StatusIdentityRejected,
		StatusSubmitted, StatusApproved, StatusRejected,
	} {
		selfService.Status = status
		if err := selfService.CanDecide(); err == nil {
			t.Errorf("self-service request in %q must not be decidable", status)
		}
	}
	selfService.Status = StatusIdentityVerified
	if err := selfService.CanDecide(); err != nil {
		t.Fatalf("identity-verified self-service request must be decidable: %v", err)
	}

	// The recorded requester is a fixed non-human actor, so maker/checker
	// blocks even a hypothetical officer whose subject collides with it.
	if err := CanApprove(SelfServiceRequesterSubject, SelfServiceRequesterSubject); !errors.Is(err, ErrMakerCheckerViolation) {
		t.Fatalf("self-service requester must never self-approve, got %v", err)
	}

	officerRequest := OnboardingRequest{Status: StatusSubmitted}
	if err := officerRequest.CanDecide(); err != nil {
		t.Fatalf("officer-submitted request must stay decidable from submitted: %v", err)
	}
	officerRequest.Status = StatusPendingVerification
	if err := officerRequest.CanDecide(); err == nil {
		t.Fatal("officer-path request must never sit in a self-service state")
	}
}

// TestIdentityReviewTransitionViolations walks every illegal KYC transition
// and proves each is denied by the state guards.
func TestIdentityReviewTransitionViolations(t *testing.T) {
	request := OnboardingRequest{Persona: "operator", Status: StatusPendingVerification}
	if err := request.CanRecordIdentityOutcome(); err == nil {
		t.Fatal("identity outcome before review start must be rejected")
	}
	if err := request.CanStartIdentityReview(); err != nil {
		t.Fatalf("pending request must enter review: %v", err)
	}
	request.Status = StatusIdentityReview
	if err := request.CanStartIdentityReview(); err == nil {
		t.Fatal("review restart must be rejected")
	}
	if err := request.CanRecordIdentityOutcome(); err != nil {
		t.Fatalf("open review must accept an outcome: %v", err)
	}
	for _, status := range []RequestStatus{StatusIdentityVerified, StatusIdentityRejected, StatusApproved, StatusActive} {
		request.Status = status
		if err := request.CanStartIdentityReview(); err == nil {
			t.Errorf("review start from %q must be rejected", status)
		}
		if err := request.CanRecordIdentityOutcome(); err == nil {
			t.Errorf("identity outcome from %q must be rejected", status)
		}
	}
	// Officer-submitted requests never enter the KYC stage at all.
	officerRequest := OnboardingRequest{Status: StatusPendingVerification}
	if err := officerRequest.CanStartIdentityReview(); err == nil {
		t.Fatal("officer-path request must be refused identity review")
	}
}

// TestIdentityVerificationInputValidation proves only approved document types
// and canonical sha256 digests are accepted; a raw document number never
// passes validation.
func TestIdentityVerificationInputValidation(t *testing.T) {
	valid := IdentityVerificationInput{
		Outcome:                 "identity_verified",
		DocumentType:            "national-id",
		DocumentReferenceSHA256: "sha256:" + strings.Repeat("a", 64),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("canonical verification input was rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*IdentityVerificationInput)
	}{
		{"raw document number instead of digest", func(input *IdentityVerificationInput) { input.DocumentReferenceSHA256 = "NIN-12345678901" }},
		{"uppercase digest", func(input *IdentityVerificationInput) {
			input.DocumentReferenceSHA256 = "sha256:" + strings.Repeat("A", 64)
		}},
		{"short digest", func(input *IdentityVerificationInput) { input.DocumentReferenceSHA256 = "sha256:abcd" }},
		{"unapproved document type", func(input *IdentityVerificationInput) { input.DocumentType = "library-card" }},
		{"unapproved outcome", func(input *IdentityVerificationInput) { input.Outcome = "verified" }},
		{"empty outcome", func(input *IdentityVerificationInput) { input.Outcome = "" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input := valid
			testCase.mutate(&input)
			if err := input.Normalize().Validate(); err == nil {
				t.Fatal("expected invalid verification input to be rejected")
			}
		})
	}
}

// TestActivationNoticeMapping proves the outbox envelope contract: fixed
// topic, type and CONFIDENTIAL classification, principal provenance, and a
// payload carrying exactly the contact-channel reference the notifier needs.
func TestActivationNoticeMapping(t *testing.T) {
	activatedAt := time.Now().UTC().Truncate(time.Second)

	selfService := OnboardingRequest{
		ID:               "request-1",
		Persona:          "trucker",
		ContactChannel:   "ussd",
		ContactReference: "+2348012345678",
		Email:            "",
	}
	notice := NewActivationNotice(selfService, "service:administration", activatedAt)
	if notice.Topic != "platform.onboarding.v1" || notice.EventType != "onboarding.activated.v1" {
		t.Fatalf("unexpected envelope identity: %#v", notice)
	}
	if notice.Classification != "CONFIDENTIAL" {
		t.Fatalf("activation notice must be CONFIDENTIAL, got %q", notice.Classification)
	}
	if notice.ProvenancePrincipal != "service:administration" {
		t.Fatalf("provenance must name the acting principal, got %q", notice.ProvenancePrincipal)
	}
	if notice.Payload.ContactChannel != "ussd" || notice.Payload.ContactReference != "+2348012345678" {
		t.Fatalf("payload must carry the recorded contact channel: %#v", notice.Payload)
	}
	if notice.Payload.RequestID != "request-1" || notice.Payload.Persona != "trucker" || !notice.Payload.ActivatedAt.Equal(activatedAt) {
		t.Fatalf("payload fields were not mapped: %#v", notice.Payload)
	}

	// Officer-path requests fall back to their approved e-mail address so
	// every activation yields a deliverable notice.
	officerRequest := OnboardingRequest{ID: "request-2", Email: "operator@example.invalid"}
	notice = NewActivationNotice(officerRequest, "service:administration", activatedAt)
	if notice.Payload.ContactChannel != "email" || notice.Payload.ContactReference != "operator@example.invalid" {
		t.Fatalf("officer-path notice must fall back to e-mail: %#v", notice.Payload)
	}
}

// TestBatchDualControlViolation proves proposer and confirmer must be
// distinct officers; the same separation is DB-enforced by the
// enrollment_batches inequality constraint.
func TestBatchDualControlViolation(t *testing.T) {
	if err := CanConfirmBatch("officer-1", "officer-1"); !errors.Is(err, ErrMakerCheckerViolation) {
		t.Fatalf("self-confirmation must be a maker/checker violation, got %v", err)
	}
	if err := CanConfirmBatch("officer-1", "officer-2"); err != nil {
		t.Fatalf("distinct officers must confirm: %v", err)
	}
	for _, subjects := range [][2]string{{"", "officer-2"}, {"officer-1", ""}, {" ", "officer-2"}} {
		if err := CanConfirmBatch(subjects[0], subjects[1]); err == nil {
			t.Fatalf("blank subjects must be rejected: %q/%q", subjects[0], subjects[1])
		}
	}
}

// TestBatchValidationAndRowIsolation proves the batch envelope bounds (1-500
// rows) and that each row is validated independently: one bad row is marked
// rejected with an explicit error and never rejects its neighbours.
func TestBatchValidationAndRowIsolation(t *testing.T) {
	var empty EnrollmentBatchInput
	if err := empty.Validate(); err == nil {
		t.Fatal("an empty batch must be rejected")
	}
	oversized := EnrollmentBatchInput{Rows: make([]EnrollmentSubmitInput, MaxEnrollmentBatchRows+1)}
	if err := oversized.Validate(); err == nil {
		t.Fatal("a batch over 500 rows must be rejected")
	}
	full := EnrollmentBatchInput{Rows: make([]EnrollmentSubmitInput, MaxEnrollmentBatchRows)}
	for index := range full.Rows {
		full.Rows[index] = validEnrollmentInput()
	}
	if err := full.Validate(); err != nil {
		t.Fatalf("a 500-row batch must be accepted: %v", err)
	}

	rows := []EnrollmentSubmitInput{validEnrollmentInput(), validEnrollmentInput(), validEnrollmentInput()}
	rows[1].Persona = "stowaway"
	results := ValidateEnrollmentRows(rows)
	if results[0] != nil || results[2] != nil {
		t.Fatalf("valid rows must stay accepted: %v", results)
	}
	if results[1] == nil || !strings.Contains(results[1].Error(), "persona") {
		t.Fatalf("the invalid row must carry an explicit per-row error: %v", results[1])
	}
}

// TestBatchNormalizeCanonicalizesRows proves every row is normalized before
// validation and storage.
func TestBatchNormalizeCanonicalizesRows(t *testing.T) {
	input := EnrollmentBatchInput{Rows: []EnrollmentSubmitInput{{
		Persona:          " fisher ",
		ContactChannel:   " sms ",
		ContactReference: " +2348012345678 ",
		FirstName:        " Adaeze ",
		LastName:         " Okafor ",
	}}}.Normalize()
	if input.Rows[0].Persona != "fisher" || input.Rows[0].ContactReference != "+2348012345678" {
		t.Fatalf("batch rows were not canonicalized: %#v", input.Rows[0])
	}
}

// TestEnrollmentOfficerRoutesRequireRoles proves the KYC and batch routes are
// officer-only: oversight roles and roleless identities are denied, officers
// pass authorization into request validation.
func TestEnrollmentOfficerRoutesRequireRoles(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		roles      []string
		wantStatus int
	}{
		{"observer denied identity review start", "/v1/enrollment/requests/abc/identity-review/start", []string{RoleCBNObserver}, http.StatusForbidden},
		{"observer denied identity outcome", "/v1/enrollment/requests/abc/identity-review/outcome", []string{RoleIndependentAuditor}, http.StatusForbidden},
		{"observer denied batch submit", "/v1/enrollment/batches", []string{RoleFMMBEOversight}, http.StatusForbidden},
		{"observer denied batch confirm", "/v1/enrollment/batches/abc/confirm", []string{RoleICRCObserver}, http.StatusForbidden},
		{"operator officer denied batch confirm", "/v1/enrollment/batches/abc/confirm", []string{RoleNWAOfficer}, http.StatusForbidden},
		{"roleless identity denied identity review", "/v1/enrollment/requests/abc/identity-review/start", nil, http.StatusForbidden},
		// Allowed roles pass authorization and reach request validation.
		{"nimasa officer passes identity outcome authz", "/v1/enrollment/requests/abc/identity-review/outcome", []string{RoleNIMASAOfficer}, http.StatusBadRequest},
		{"niwa officer passes batch submit authz", "/v1/enrollment/batches", []string{RoleNIWAOfficer}, http.StatusBadRequest},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			service := newStubService(testCase.roles...)
			recorder := httptest.NewRecorder()
			service.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, testCase.path, strings.NewReader(`{}`)))
			if recorder.Code != testCase.wantStatus {
				t.Fatalf("got %d, want %d (body: %s)", recorder.Code, testCase.wantStatus, recorder.Body.String())
			}
		})
	}
}

// TestTruncateBatchErrorBoundsStoredFailure proves per-row failure messages
// stay within the storage contract.
func TestTruncateBatchErrorBoundsStoredFailure(t *testing.T) {
	if got := truncateBatchError("short"); got != "short" {
		t.Fatalf("short message must pass through, got %q", got)
	}
	if got := truncateBatchError(strings.Repeat("x", 5000)); len(got) != 1024 {
		t.Fatalf("oversized message must be truncated to 1024, got %d", len(got))
	}
}
