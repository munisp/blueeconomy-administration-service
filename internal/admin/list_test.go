package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/munisp/blueeconomy-administration-service/internal/pbac"
)

// --- non-database authorization and validation tests ---

// TestListQueueAuthorizationDenials proves the approver-only queue fails
// closed for every caller class that must never see it, without a database:
// authorization and PBAC deny before any storage access.
func TestListQueueAuthorizationDenials(t *testing.T) {
	cases := []struct {
		name       string
		identity   AuthenticatedIdentity
		authErr    error
		wantStatus int
	}{
		{
			name:       "unauthenticated caller is 401",
			authErr:    errors.New("Bearer authorization is required"),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "roleless identity is 403",
			identity:   AuthenticatedIdentity{Subject: "s-1", TenantID: "stub-tenant"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "operator-only officer is 403",
			identity:   AuthenticatedIdentity{Subject: "s-1", Roles: roleSet(RoleNWAOfficer), TenantID: "stub-tenant"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "read-only observer is 403",
			identity:   AuthenticatedIdentity{Subject: "s-1", Roles: roleSet(RoleCBNObserver), TenantID: "stub-tenant"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "tenant-less approver is denied by PBAC tenant scope",
			identity:   AuthenticatedIdentity{Subject: "s-1", Roles: roleSet(RoleNIMASAOfficer)},
			wantStatus: http.StatusForbidden,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			service := &HTTPService{
				authenticator: stubAuthenticator{identity: testCase.identity, err: testCase.authErr},
				tenantLookup:  stubTenantLookup{},
			}
			engine := mustLoadTestPolicyEngine(t)
			service.SetPBACEngine(engine)
			recorder := httptest.NewRecorder()
			service.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/onboarding/requests", nil))
			if recorder.Code != testCase.wantStatus {
				t.Fatalf("got %d, want %d (body: %s)", recorder.Code, testCase.wantStatus, recorder.Body.String())
			}
		})
	}
}

// TestListQueueDeniedWithoutPolicyEngine proves the fail-closed stance: an
// approver with a valid tenant claim is still denied when no policy engine is
// attached.
func TestListQueueDeniedWithoutPolicyEngine(t *testing.T) {
	service := &HTTPService{
		authenticator: stubAuthenticator{identity: AuthenticatedIdentity{Subject: "s-1", Roles: roleSet(RoleNIMASAOfficer), TenantID: "stub-tenant"}},
		tenantLookup:  stubTenantLookup{},
	}
	recorder := httptest.NewRecorder()
	service.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/onboarding/requests", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("missing policy engine must deny with 403, got %d", recorder.Code)
	}
}

func TestParseListFilterValidation(t *testing.T) {
	cases := []struct {
		name    string
		query   map[string][]string
		wantErr bool
	}{
		{"defaults", map[string][]string{}, false},
		{"approved status filter", map[string][]string{"status": {"pending"}}, false},
		{"unknown status filter rejected", map[string][]string{"status": {"provisioning"}}, true},
		{"empty limit rejected", map[string][]string{"limit": {"0"}}, true},
		{"oversized limit rejected", map[string][]string{"limit": {fmt.Sprintf("%d", ListMaxLimit+1)}}, true},
		{"non-numeric limit rejected", map[string][]string{"limit": {"abc"}}, true},
		{"bounded limit accepted", map[string][]string{"limit": {"100"}}, false},
		{"negative offset rejected", map[string][]string{"offset": {"-1"}}, true},
		{"non-numeric offset rejected", map[string][]string{"offset": {"x"}}, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := parseListFilter(testCase.query)
			if testCase.wantErr && err == nil {
				t.Fatal("expected the query to be rejected")
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("expected the query to pass, got %v", err)
			}
		})
	}
	for _, group := range []string{"pending", "decided", "provisioned", "active", "rejected"} {
		if _, known := listStatusGroups[group]; !known {
			t.Fatalf("approved queue filter %q must map to raw statuses", group)
		}
	}
}

// --- database-gated behaviour tests (integration convention) ---

func listTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("ADMIN_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("ADMIN_TEST_POSTGRES_DSN is not set; skipping database-gated onboarding queue test")
	}
	store, err := NewStore(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

// mustLoadTestPolicyEngine compiles the shipped fleet policy directory, the
// same engine main() attaches at startup.
func mustLoadTestPolicyEngine(t *testing.T) *pbac.Engine {
	t.Helper()
	engine, err := pbac.LoadPolicyDir(filepath.Join("..", "..", "policies"))
	if err != nil {
		t.Fatalf("load shipped policy engine: %v", err)
	}
	return engine
}

// listQueueService builds the real HTTP stack against a live store with the
// shipped PBAC policy; only the credential itself is stubbed.
func listQueueService(t *testing.T, store *Store, identity AuthenticatedIdentity) *HTTPService {
	t.Helper()
	service := &HTTPService{
		store:         store,
		authenticator: stubAuthenticator{identity: identity},
		tenantLookup:  store,
	}
	service.SetPBACEngine(mustLoadTestPolicyEngine(t))
	return service
}

type queueFixture struct {
	tenantA string
	tenantB string
	ids     map[string]string // label -> request id
}

// insertQueueRows seeds two tenants with every lifecycle status the queue
// filter groups must recognise.
func insertQueueRows(t *testing.T, store *Store) queueFixture {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	fixture := queueFixture{
		tenantA: "queue-tenant-a-" + suffix,
		tenantB: "queue-tenant-b-" + suffix,
		ids:     map[string]string{},
	}
	insert := func(tenant, label, status, persona string) {
		t.Helper()
		email := label + "-" + suffix + "@example.invalid"
		roles := "{nimasa-officer}"
		contactChannel, contactReference := "", ""
		if persona != "" {
			email = ""
			roles = "{}"
			contactChannel = "sms"
			contactReference = "+23480" + suffix[len(suffix)-7:]
		}
		var id string
		const query = `
		INSERT INTO onboarding_requests (organization_id, email, first_name, last_name, requested_roles, requester_subject, status, persona, contact_channel, contact_reference)
		VALUES ($1, $2, 'Queue', 'Test', $3, 'queue-test-officer', $4, $5, $6, $7)
		RETURNING id::text`
		if err := store.pool.QueryRow(ctx, query, tenant, email, roles, status, persona, contactChannel, contactReference).Scan(&id); err != nil {
			t.Fatalf("insert %s row: %v", label, err)
		}
		fixture.ids[label] = id
	}
	insert(fixture.tenantA, "submitted", "submitted", "")
	insert(fixture.tenantA, "approved", "approved", "")
	insert(fixture.tenantA, "invited", "invited", "")
	insert(fixture.tenantA, "active", "active", "")
	insert(fixture.tenantA, "rejected", "rejected", "")
	insert(fixture.tenantA, "pending-verification", "pending_verification", "fisher")
	insert(fixture.tenantB, "foreign-submitted", "submitted", "")
	insert(fixture.tenantB, "foreign-active", "active", "")
	return fixture
}

func getQueue(t *testing.T, service *HTTPService, path string) (int, OnboardingListResponse) {
	t.Helper()
	recorder := httptest.NewRecorder()
	service.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	var response OnboardingListResponse
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("queue response is not the documented envelope: %v", err)
		}
	}
	return recorder.Code, response
}

// TestListQueueTenantIsolation proves the tenant claim scopes the queue end
// to end: tenant A's approver never sees tenant B's requests, in any filter.
func TestListQueueTenantIsolation(t *testing.T) {
	store := listTestStore(t)
	fixture := insertQueueRows(t, store)
	service := listQueueService(t, store, AuthenticatedIdentity{Subject: "approver-1", Roles: roleSet(RoleNIMASAOfficer), TenantID: fixture.tenantA})

	code, response := getQueue(t, service, "/v1/onboarding/requests")
	if code != http.StatusOK {
		t.Fatalf("queue read failed: %d", code)
	}
	if response.Page.Total != 6 || len(response.Requests) != 6 {
		t.Fatalf("tenant A queue must hold exactly its 6 requests, got total=%d len=%d", response.Page.Total, len(response.Requests))
	}
	foreign := map[string]struct{}{fixture.ids["foreign-submitted"]: {}, fixture.ids["foreign-active"]: {}}
	for _, request := range response.Requests {
		if _, leaked := foreign[request.ID]; leaked {
			t.Fatalf("cross-tenant request %s leaked into tenant A queue", request.ID)
		}
		if request.OrganizationID != fixture.tenantA {
			t.Fatalf("queue row carries foreign organization %q", request.OrganizationID)
		}
	}
}

// TestListQueueFilterCorrectness proves every approved status group maps to
// exactly its raw lifecycle statuses.
func TestListQueueFilterCorrectness(t *testing.T) {
	store := listTestStore(t)
	fixture := insertQueueRows(t, store)
	service := listQueueService(t, store, AuthenticatedIdentity{Subject: "approver-1", Roles: roleSet(RoleNIMASAOfficer), TenantID: fixture.tenantA})

	cases := []struct {
		filter string
		labels []string
	}{
		{"pending", []string{"submitted", "pending-verification"}},
		{"decided", []string{"approved"}},
		{"provisioned", []string{"invited"}},
		{"active", []string{"active"}},
		{"rejected", []string{"rejected"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.filter, func(t *testing.T) {
			code, response := getQueue(t, service, "/v1/onboarding/requests?status="+testCase.filter)
			if code != http.StatusOK {
				t.Fatalf("filtered queue read failed: %d", code)
			}
			if len(response.Requests) != len(testCase.labels) || response.Page.Total != len(testCase.labels) {
				t.Fatalf("filter %s returned %d rows, want %d", testCase.filter, len(response.Requests), len(testCase.labels))
			}
			want := map[string]struct{}{}
			for _, label := range testCase.labels {
				want[fixture.ids[label]] = struct{}{}
			}
			for _, request := range response.Requests {
				if _, ok := want[request.ID]; !ok {
					t.Fatalf("filter %s returned unexpected request %s (status %s)", testCase.filter, request.ID, request.Status)
				}
			}
		})
	}

	if code, _ := getQueue(t, service, "/v1/onboarding/requests?status=unknown"); code != http.StatusBadRequest {
		t.Fatalf("unknown status filter must be 400, got %d", code)
	}
}

// TestListQueuePagination proves bounded pages, deterministic created_at/id
// ordering and the next_offset contract across the whole queue.
func TestListQueuePagination(t *testing.T) {
	store := listTestStore(t)
	fixture := insertQueueRows(t, store)
	service := listQueueService(t, store, AuthenticatedIdentity{Subject: "approver-1", Roles: roleSet(RoleNIMASAOfficer), TenantID: fixture.tenantA})

	var seen []string
	offset := 0
	pages := 0
	for {
		code, response := getQueue(t, service, fmt.Sprintf("/v1/onboarding/requests?limit=2&offset=%d", offset))
		if code != http.StatusOK {
			t.Fatalf("paged queue read failed: %d", code)
		}
		if response.Page.Limit != 2 || response.Page.Offset != offset || response.Page.Total != 6 {
			t.Fatalf("page envelope wrong: %+v", response.Page)
		}
		for _, request := range response.Requests {
			seen = append(seen, request.ID)
		}
		pages++
		if response.Page.NextOffset == nil {
			break
		}
		offset = *response.Page.NextOffset
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != 6 {
		t.Fatalf("walked %d rows across pages, want 6", len(seen))
	}
	// Deterministic ascending created_at order, no duplicates across pages.
	duplicates := map[string]struct{}{}
	var previous time.Time
	first := true
	for _, id := range seen {
		if _, dup := duplicates[id]; dup {
			t.Fatalf("request %s appeared on two pages", id)
		}
		duplicates[id] = struct{}{}
	}
	code, response := getQueue(t, service, "/v1/onboarding/requests?limit=3")
	if code != http.StatusOK {
		t.Fatalf("queue read failed: %d", code)
	}
	for _, request := range response.Requests {
		if !first && request.CreatedAt.Before(previous) {
			t.Fatal("queue is not ordered by created_at ascending")
		}
		first = false
		previous = request.CreatedAt
	}

	for _, badPath := range []string{
		"/v1/onboarding/requests?limit=0",
		"/v1/onboarding/requests?limit=101",
		"/v1/onboarding/requests?limit=abc",
		"/v1/onboarding/requests?offset=-1",
	} {
		if code, _ := getQueue(t, service, badPath); code != http.StatusBadRequest {
			t.Fatalf("%s must be 400, got %d", badPath, code)
		}
	}
}

// TestListQueueApproverRolesCanRead proves both approver roles pass the full
// middleware stack and reach storage; the response carries the documented
// envelope fields.
func TestListQueueApproverRolesCanRead(t *testing.T) {
	store := listTestStore(t)
	fixture := insertQueueRows(t, store)
	for _, role := range []string{RolePlatformAdmin, RoleNIMASAOfficer} {
		service := listQueueService(t, store, AuthenticatedIdentity{Subject: "approver-1", Roles: roleSet(role), TenantID: fixture.tenantA})
		code, response := getQueue(t, service, "/v1/onboarding/requests?status=active")
		if code != http.StatusOK {
			t.Fatalf("role %s must read the queue, got %d", role, code)
		}
		if response.Page.Total != 1 || len(response.Requests) != 1 || response.Requests[0].ID != fixture.ids["active"] {
			t.Fatalf("role %s active filter wrong: %+v", role, response)
		}
		first := response.Requests[0]
		if first.Email == "" || first.FirstName == "" || first.Status != StatusActive || first.CreatedAt.IsZero() {
			t.Fatalf("queue row is missing documented fields: %+v", first)
		}
	}
}
