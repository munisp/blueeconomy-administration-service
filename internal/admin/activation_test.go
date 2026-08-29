package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// --- fakes for the activation boundary ---

type activationClaim struct {
	requestID      string
	keycloakUserID string
}

type activationResult struct {
	requestID    string
	actorSubject string
	success      bool
	reason       string
}

// fakeOnboardingStore implements only the activation surface; the embedded
// interface turns any unexpected call into a loud nil-method panic.
type fakeOnboardingStore struct {
	onboardingStore
	requests   map[string]OnboardingRequest
	getCalls   int
	claims     []activationClaim
	results    []activationResult
	claimError error
}

func (fake *fakeOnboardingStore) Get(_ context.Context, id string) (OnboardingRequest, error) {
	fake.getCalls++
	candidate, exists := fake.requests[id]
	if !exists {
		return OnboardingRequest{}, ErrNotFound
	}
	return candidate, nil
}

func (fake *fakeOnboardingStore) ClaimActivation(_ context.Context, id, keycloakUserID string) (OnboardingRequest, error) {
	if fake.claimError != nil {
		return OnboardingRequest{}, fake.claimError
	}
	fake.claims = append(fake.claims, activationClaim{requestID: id, keycloakUserID: keycloakUserID})
	return fake.requests[id], nil
}

func (fake *fakeOnboardingStore) RecordActivationResult(_ context.Context, id, actorSubject string, success bool, reason string) error {
	fake.results = append(fake.results, activationResult{requestID: id, actorSubject: actorSubject, success: success, reason: reason})
	return nil
}

// fakeKeycloakAdmin resolves e-mail addresses from a fixed directory, like
// the Keycloak admin API, and records every group assignment.
type fakeKeycloakAdmin struct {
	keycloakAdmin
	usersByEmail   map[string]string
	lookupError    error
	lookedUpEmails []string
	assignError    error
	assignments    []activationClaim
	assignedRoles  [][]string
}

func (fake *fakeKeycloakAdmin) FindUserIDByEmail(_ context.Context, email string) (string, error) {
	fake.lookedUpEmails = append(fake.lookedUpEmails, email)
	if fake.lookupError != nil {
		return "", fake.lookupError
	}
	id, exists := fake.usersByEmail[strings.ToLower(strings.TrimSpace(email))]
	if !exists {
		return "", ErrKeycloakUserNotFound
	}
	return id, nil
}

func (fake *fakeKeycloakAdmin) AssignApprovedRoleGroups(_ context.Context, keycloakUserID string, roles []string) error {
	if fake.assignError != nil {
		return fake.assignError
	}
	fake.assignments = append(fake.assignments, activationClaim{keycloakUserID: keycloakUserID})
	fake.assignedRoles = append(fake.assignedRoles, roles)
	return nil
}

func newActivationService(store *fakeOnboardingStore, keycloak *fakeKeycloakAdmin) *HTTPService {
	return &HTTPService{
		store:    store,
		keycloak: keycloak,
		authenticator: stubAuthenticator{identity: AuthenticatedIdentity{
			Subject:  "officer-7",
			Roles:    roleSet(RoleNIMASAOfficer),
			TenantID: "tenant-1",
		}},
	}
}

func invitedCandidate() OnboardingRequest {
	return OnboardingRequest{
		ID:             "request-1",
		OrganizationID: "tenant-1",
		Email:          "Vetted.Candidate@example.invalid",
		FirstName:      "Vetted",
		LastName:       "Candidate",
		RequestedRoles: []string{"nimasa-officer"},
		Status:         StatusInvited,
	}
}

func activationRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/onboarding/requests/request-1/activate", reader)
	request.SetPathValue("id", "request-1")
	return request
}

// TestActivateRejectsClientSuppliedKeycloakUserID is the AD-1 regression
// gate: a foreign keycloak_user_id in the body is rejected before any store
// or Keycloak call, so an officer (or a stolen token) can never steer the
// approved role groups to an arbitrary account.
func TestActivateRejectsClientSuppliedKeycloakUserID(t *testing.T) {
	store := &fakeOnboardingStore{requests: map[string]OnboardingRequest{"request-1": invitedCandidate()}}
	keycloak := &fakeKeycloakAdmin{usersByEmail: map[string]string{"vetted.candidate@example.invalid": "kc-vetted-1"}}
	service := newActivationService(store, keycloak)

	for _, body := range []string{
		`{"keycloak_user_id":"attacker-alt-account"}`,
		`{"keycloak_user_id":"  "}`,
	} {
		recorder := httptest.NewRecorder()
		service.activate(recorder, activationRequest(t, body))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("body %s: expected 400, got %d (%s)", body, recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), "keycloak_user_id must not be supplied") {
			t.Fatalf("body %s: rejection must name the misuse, got %s", body, recorder.Body.String())
		}
	}
	if store.getCalls != 0 || len(store.claims) != 0 || len(store.results) != 0 {
		t.Fatalf("rejection must happen before persistence: gets=%d claims=%v results=%v", store.getCalls, store.claims, store.results)
	}
	if len(keycloak.assignments) != 0 || len(keycloak.lookedUpEmails) != 0 {
		t.Fatalf("rejection must happen before Keycloak: lookups=%v assignments=%v", keycloak.lookedUpEmails, keycloak.assignments)
	}
}

// TestActivateBindsVettedIdentityOnly proves the roles land exclusively on
// the Keycloak user resolved from the vetted e-mail: the claim, the group
// assignment and the audit decision all carry the server-resolved identity,
// and the audit records both principals (activating officer + recipient).
func TestActivateBindsVettedIdentityOnly(t *testing.T) {
	candidate := invitedCandidate()
	store := &fakeOnboardingStore{requests: map[string]OnboardingRequest{"request-1": candidate}}
	keycloak := &fakeKeycloakAdmin{usersByEmail: map[string]string{"vetted.candidate@example.invalid": "kc-vetted-1"}}
	service := newActivationService(store, keycloak)

	recorder := httptest.NewRecorder()
	service.activate(recorder, activationRequest(t, ""))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	if len(keycloak.lookedUpEmails) != 1 || keycloak.lookedUpEmails[0] != candidate.Email {
		t.Fatalf("lookup must use the vetted e-mail from the stored request, got %v", keycloak.lookedUpEmails)
	}
	if len(store.claims) != 1 || store.claims[0].keycloakUserID != "kc-vetted-1" {
		t.Fatalf("claim must bind the server-resolved user, got %v", store.claims)
	}
	if len(keycloak.assignments) != 1 || keycloak.assignments[0].keycloakUserID != "kc-vetted-1" {
		t.Fatalf("assignment must target only the vetted identity, got %v", keycloak.assignments)
	}
	if len(keycloak.assignedRoles) != 1 || len(keycloak.assignedRoles[0]) != 1 || keycloak.assignedRoles[0][0] != "nimasa-officer" {
		t.Fatalf("assignment must carry the approved roles, got %v", keycloak.assignedRoles)
	}

	if len(store.results) != 1 {
		t.Fatalf("exactly one audit decision must be recorded, got %v", store.results)
	}
	result := store.results[0]
	if !result.success {
		t.Fatalf("successful activation must record a success decision: %v", result)
	}
	if result.actorSubject != "officer-7" {
		t.Fatalf("audit must name the activating officer, got %q", result.actorSubject)
	}
	if !strings.Contains(result.reason, candidate.Email) || !strings.Contains(result.reason, "kc-vetted-1") {
		t.Fatalf("audit must name the receiving identity (e-mail + Keycloak user), got %q", result.reason)
	}
}

// TestActivateFailsClosedWithoutKeycloakUser proves that when no Keycloak
// user exists for the vetted e-mail the request is denied (409) and nothing
// is claimed, assigned or recorded.
func TestActivateFailsClosedWithoutKeycloakUser(t *testing.T) {
	store := &fakeOnboardingStore{requests: map[string]OnboardingRequest{"request-1": invitedCandidate()}}
	keycloak := &fakeKeycloakAdmin{usersByEmail: map[string]string{}}
	service := newActivationService(store, keycloak)

	recorder := httptest.NewRecorder()
	service.activate(recorder, activationRequest(t, ""))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("missing Keycloak user must fail closed with 409, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "no unique enabled Keycloak user") {
		t.Fatalf("rejection must state the honest reason, got %s", recorder.Body.String())
	}
	if len(store.claims) != 0 || len(store.results) != 0 || len(keycloak.assignments) != 0 {
		t.Fatalf("fail-closed means no claim, assignment or audit: claims=%v results=%v assignments=%v", store.claims, store.results, keycloak.assignments)
	}
}

// TestActivateFailsClosedOnLookupOutage proves a Keycloak lookup failure is
// a bad-gateway denial, not a guess: no claim or assignment follows.
func TestActivateFailsClosedOnLookupOutage(t *testing.T) {
	store := &fakeOnboardingStore{requests: map[string]OnboardingRequest{"request-1": invitedCandidate()}}
	keycloak := &fakeKeycloakAdmin{lookupError: errors.New("keycloak unreachable")}
	service := newActivationService(store, keycloak)

	recorder := httptest.NewRecorder()
	service.activate(recorder, activationRequest(t, ""))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("lookup outage must yield 502, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if len(store.claims) != 0 || len(keycloak.assignments) != 0 {
		t.Fatalf("fail-closed means no claim or assignment: claims=%v assignments=%v", store.claims, keycloak.assignments)
	}
}

// TestActivateFailsClosedWithoutVettedEmail proves a vetted request that
// carries no e-mail address can never reach a Keycloak lookup or claim.
func TestActivateFailsClosedWithoutVettedEmail(t *testing.T) {
	candidate := invitedCandidate()
	candidate.Email = ""
	store := &fakeOnboardingStore{requests: map[string]OnboardingRequest{"request-1": candidate}}
	keycloak := &fakeKeycloakAdmin{usersByEmail: map[string]string{}}
	service := newActivationService(store, keycloak)

	recorder := httptest.NewRecorder()
	service.activate(recorder, activationRequest(t, ""))
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing vetted e-mail must fail closed with 422, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if len(keycloak.lookedUpEmails) != 0 || len(store.claims) != 0 || len(keycloak.assignments) != 0 {
		t.Fatalf("no identity work may happen without a vetted e-mail: lookups=%v claims=%v assignments=%v", keycloak.lookedUpEmails, store.claims, keycloak.assignments)
	}
}

// TestActivateUnknownRequestIsNotFound keeps the missing-request contract
// explicit: 404, and no identity resolution is attempted.
func TestActivateUnknownRequestIsNotFound(t *testing.T) {
	store := &fakeOnboardingStore{requests: map[string]OnboardingRequest{}}
	keycloak := &fakeKeycloakAdmin{usersByEmail: map[string]string{}}
	service := newActivationService(store, keycloak)

	recorder := httptest.NewRecorder()
	service.activate(recorder, activationRequest(t, ""))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown request must be 404, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if len(keycloak.lookedUpEmails) != 0 || len(store.claims) != 0 {
		t.Fatalf("no identity work may happen for an unknown request: lookups=%v claims=%v", keycloak.lookedUpEmails, store.claims)
	}
}

// TestActivateAssignmentFailureRecordsFailedAudit proves the ambiguous
// outcome path also names the acting officer rather than a bare service
// identity.
func TestActivateAssignmentFailureRecordsFailedAudit(t *testing.T) {
	store := &fakeOnboardingStore{requests: map[string]OnboardingRequest{"request-1": invitedCandidate()}}
	keycloak := &fakeKeycloakAdmin{
		usersByEmail: map[string]string{"vetted.candidate@example.invalid": "kc-vetted-1"},
		assignError:  errors.New("group assignment returned HTTP 500"),
	}
	service := newActivationService(store, keycloak)

	recorder := httptest.NewRecorder()
	service.activate(recorder, activationRequest(t, ""))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("assignment failure must yield 502, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if len(store.results) != 1 || store.results[0].success || store.results[0].actorSubject != "officer-7" {
		t.Fatalf("failed activation must record a failed audit by the officer, got %v", store.results)
	}
}

// --- Keycloak admin client e-mail resolution ---

func newKeycloakLookupFixture(t *testing.T, users []map[string]any, requests *[][]string) *KeycloakClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if requests != nil {
			*requests = append(*requests, []string{request.Method, request.URL.Path, request.URL.RawQuery})
		}
		switch {
		case strings.HasSuffix(request.URL.Path, "/token"):
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "token-1", "token_type": "Bearer", "expires_in": 300})
		case strings.HasSuffix(request.URL.Path, "/users"):
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(users)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	tokenURL, err := url.Parse(server.URL + "/realms/blueeconomy/protocol/openid-connect/token")
	if err != nil {
		t.Fatal(err)
	}
	adminBaseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &KeycloakClient{
		httpClient:     server.Client(),
		tokenURL:       tokenURL,
		adminBaseURL:   adminBaseURL,
		realm:          "blueeconomy",
		organizationID: "org-1",
		clientID:       "admin-service",
		clientSecret:   "secret",
	}
}

// TestFindUserIDByEmailResolvesExactlyOneEnabledUser proves the lookup asks
// Keycloak for an exact e-mail match and accepts only enabled users whose
// e-mail matches case-insensitively.
func TestFindUserIDByEmailResolvesExactlyOneEnabledUser(t *testing.T) {
	var requests [][]string
	client := newKeycloakLookupFixture(t, []map[string]any{
		{"id": "kc-disabled", "email": "vetted@example.invalid", "enabled": false},
		{"id": "kc-other", "email": "other@example.invalid", "enabled": true},
		{"id": "kc-vetted-1", "email": "Vetted@example.invalid", "enabled": true},
	}, &requests)

	id, err := client.FindUserIDByEmail(context.Background(), "vetted@example.invalid")
	if err != nil {
		t.Fatalf("expected resolution, got %v", err)
	}
	if id != "kc-vetted-1" {
		t.Fatalf("must resolve the enabled exact-match user, got %q", id)
	}
	var lookupQuery string
	for _, call := range requests {
		if strings.HasSuffix(call[1], "/users") {
			lookupQuery = call[2]
		}
	}
	if !strings.Contains(lookupQuery, "email=vetted%40example.invalid") || !strings.Contains(lookupQuery, "exact=true") {
		t.Fatalf("lookup must query Keycloak by exact e-mail, got %q", lookupQuery)
	}
}

// TestFindUserIDByEmailFailsClosed proves the fail-closed outcomes: no
// enabled match, and ambiguous matches, both deny activation.
func TestFindUserIDByEmailFailsClosed(t *testing.T) {
	t.Run("no enabled user", func(t *testing.T) {
		client := newKeycloakLookupFixture(t, []map[string]any{
			{"id": "kc-disabled", "email": "vetted@example.invalid", "enabled": false},
		}, nil)
		if _, err := client.FindUserIDByEmail(context.Background(), "vetted@example.invalid"); !errors.Is(err, ErrKeycloakUserNotFound) {
			t.Fatalf("expected ErrKeycloakUserNotFound, got %v", err)
		}
	})
	t.Run("no users at all", func(t *testing.T) {
		client := newKeycloakLookupFixture(t, []map[string]any{}, nil)
		if _, err := client.FindUserIDByEmail(context.Background(), "vetted@example.invalid"); !errors.Is(err, ErrKeycloakUserNotFound) {
			t.Fatalf("expected ErrKeycloakUserNotFound, got %v", err)
		}
	})
	t.Run("ambiguous enabled users", func(t *testing.T) {
		client := newKeycloakLookupFixture(t, []map[string]any{
			{"id": "kc-1", "email": "vetted@example.invalid", "enabled": true},
			{"id": "kc-2", "email": "vetted@example.invalid", "enabled": true},
		}, nil)
		if _, err := client.FindUserIDByEmail(context.Background(), "vetted@example.invalid"); !errors.Is(err, ErrKeycloakUserAmbiguous) {
			t.Fatalf("expected ErrKeycloakUserAmbiguous, got %v", err)
		}
	})
	t.Run("empty e-mail never leaves the service", func(t *testing.T) {
		var requests [][]string
		client := newKeycloakLookupFixture(t, nil, &requests)
		if _, err := client.FindUserIDByEmail(context.Background(), "  "); err == nil {
			t.Fatal("an empty vetted e-mail must be rejected")
		}
		if len(requests) != 0 {
			t.Fatalf("no Keycloak call may happen for an empty e-mail, got %v", requests)
		}
	})
}
