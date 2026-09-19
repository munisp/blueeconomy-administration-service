package admin

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubAuthenticator struct {
	principal Principal
	err       error
}

func (stub stubAuthenticator) Authenticate(*http.Request) (Principal, error) {
	return stub.principal, stub.err
}

func newTestService(authenticator subjectAuthenticator) *HTTPService {
	return &HTTPService{
		organizationID: "org-1",
		allowedRoles:   map[string]struct{}{"beneficiary": struct{}{}},
		serviceActor:   "service-actor",
		approverRole:   DefaultApproverRole,
		authenticator:  authenticator,
	}
}

func TestPrivilegedRoutesForbiddenWithoutApproverRole(t *testing.T) {
	service := newTestService(stubAuthenticator{principal: Principal{Subject: "subject-1", Roles: []string{"beneficiary"}}})
	handler := service.Handler()
	for _, route := range []string{
		"/v1/onboarding/requests/00000000-0000-0000-0000-000000000001/decision",
		"/v1/onboarding/requests/00000000-0000-0000-0000-000000000001/provision",
		"/v1/onboarding/requests/00000000-0000-0000-0000-000000000001/activate",
	} {
		body := `{"decision":"approve","reason":"ok","keycloak_user_id":"kc-1"}`
		request := httptest.NewRequest("POST", route, strings.NewReader(body))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("POST %s: expected 403 for non-approver, got %d", route, recorder.Code)
		}
	}
}

func TestPrivilegedRoutesUnauthenticatedWithoutCredentials(t *testing.T) {
	service := newTestService(stubAuthenticator{err: errors.New("no credentials")})
	handler := service.Handler()
	for _, route := range []string{
		"/v1/onboarding/requests/00000000-0000-0000-0000-000000000001/decision",
		"/v1/onboarding/requests/00000000-0000-0000-0000-000000000001/provision",
		"/v1/onboarding/requests/00000000-0000-0000-0000-000000000001/activate",
		"/v1/onboarding/requests",
	} {
		request := httptest.NewRequest("POST", route, strings.NewReader(`{}`))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("POST %s: expected 401 for unauthenticated caller, got %d", route, recorder.Code)
		}
	}
}

func TestApproverRoleMismatchIsForbiddenEvenWithOtherRoles(t *testing.T) {
	service := newTestService(stubAuthenticator{principal: Principal{Subject: "subject-9", Roles: []string{"platform-admin", "nimasa-officer"}}})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/v1/onboarding/requests/00000000-0000-0000-0000-000000000001/decision", strings.NewReader(`{"decision":"approve"}`))
	service.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when the approver role is absent, got %d", recorder.Code)
	}
}

func TestTrustedProxyAuthenticatorExtractsRoles(t *testing.T) {
	_, network, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	authenticator := trustedProxyAuthenticator{cidrs: []*net.IPNet{network}, identity: "apisix-edge"}
	request := httptest.NewRequest("POST", "/", nil)
	request.RemoteAddr = "10.1.2.3:4444"
	request.Header.Set("X-Blueeconomy-Authenticated-By", "apisix-edge")
	request.Header.Set("X-Blueeconomy-Authenticated-Subject", "subject-7")
	request.Header.Set(trustedProxyRolesHeader, "onboarding-approver, auditor")
	principal, err := authenticator.Authenticate(request)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if principal.Subject != "subject-7" || !principal.HasRole("onboarding-approver") || !principal.HasRole("auditor") {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	if principal.HasRole("platform-admin") {
		t.Fatal("principal must not hold unasserted roles")
	}
}

func TestTrustedProxyAuthenticatorRejectsMalformedRole(t *testing.T) {
	_, network, _ := net.ParseCIDR("10.0.0.0/8")
	authenticator := trustedProxyAuthenticator{cidrs: []*net.IPNet{network}, identity: "apisix-edge"}
	request := httptest.NewRequest("POST", "/", nil)
	request.RemoteAddr = "10.1.2.3:4444"
	request.Header.Set("X-Blueeconomy-Authenticated-By", "apisix-edge")
	request.Header.Set("X-Blueeconomy-Authenticated-Subject", "subject-7")
	request.Header.Set(trustedProxyRolesHeader, "onboarding-approver,Admin;DROP")
	if _, err := authenticator.Authenticate(request); err == nil {
		t.Fatal("expected malformed asserted role to be rejected")
	}
}

func TestRolesFromClaimsFiltersAndDeduplicates(t *testing.T) {
	authenticator := &oidcAuthenticator{rolesClientIDs: []string{"admin-console"}}
	resourceAccess := map[string]struct {
		Roles []string `json:"roles"`
	}{
		"admin-console": {Roles: []string{"onboarding-approver", "onboarding-approver", "Not A Role"}},
		"other-client":  {Roles: []string{"platform-admin"}},
	}
	roles := authenticator.rolesFromClaims([]string{"auditor", "Invalid Role"}, resourceAccess)
	joined := strings.Join(roles, ",")
	if joined != "auditor,onboarding-approver" {
		t.Fatalf("unexpected role set: %q", joined)
	}
}

func TestLoadConfigDefaultsApproverRole(t *testing.T) {
	t.Setenv("ADMIN_SERVICE_LISTEN_ADDRESS", ":8080")
	t.Setenv("ADMIN_SERVICE_POSTGRES_DSN", "postgres://example")
	t.Setenv("ADMIN_AUTH_MODE", "trusted_proxy")
	t.Setenv("ADMIN_TRUSTED_PROXY_IDENTITY", "apisix-edge")
	t.Setenv("ADMIN_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
	t.Setenv("KEYCLOAK_TOKEN_URL", "https://keycloak.example.invalid/token")
	t.Setenv("KEYCLOAK_ADMIN_BASE_URL", "https://keycloak.example.invalid/admin")
	t.Setenv("KEYCLOAK_REALM", "blueeconomy-platform")
	t.Setenv("KEYCLOAK_ORGANIZATION_ID", "org-1")
	t.Setenv("KEYCLOAK_ADMIN_CLIENT_ID", "administration-service")
	t.Setenv("KEYCLOAK_ADMIN_CLIENT_SECRET", "secret")
	t.Setenv("KEYCLOAK_SERVICE_ACTOR_SUBJECT", "service-actor")
	t.Setenv("ONBOARDING_ALLOWED_ROLES", "platform-admin")
	t.Setenv("KEYCLOAK_ROLE_GROUP_MAPPING_JSON", `{"platform-admin":"group-1"}`)
	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if config.ApproverRole != DefaultApproverRole {
		t.Fatalf("expected default approver role %q, got %q", DefaultApproverRole, config.ApproverRole)
	}
}

func TestLoadConfigRejectsMalformedApproverRole(t *testing.T) {
	TestLoadConfigDefaultsApproverRole(t)
	t.Setenv("ADMIN_ONBOARDING_APPROVER_ROLE", "Not A Role")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected malformed ADMIN_ONBOARDING_APPROVER_ROLE to be rejected")
	}
}
