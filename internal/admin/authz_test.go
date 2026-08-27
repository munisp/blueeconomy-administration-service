package admin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var allRealmRoles = []string{
	RolePlatformAdmin,
	RoleNIMASAOfficer,
	RoleNWAOfficer,
	RoleNIWAOfficer,
	RoleCBNObserver,
	RoleFMMBEOversight,
	RoleIndependentAuditor,
	RoleICRCObserver,
}

func roleSet(roles ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		set[role] = struct{}{}
	}
	return set
}

func isMutating(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

// TestRoutePolicyRoleMatrix walks every registered route against every realm
// role and asserts the exact allowed/denied outcome. Any route added to the
// table without a policy review fails this test.
func TestRoutePolicyRoleMatrix(t *testing.T) {
	service := &HTTPService{}
	routes := service.routes()
	if len(routes) != 11 {
		t.Fatalf("route table changed without a policy review: %d routes", len(routes))
	}
	for pattern, policy := range routes {
		method, _, _ := strings.Cut(pattern, " ")
		if len(policy.allowedRoles) == 0 {
			if pattern != "GET /healthz" && pattern != "GET /readyz" {
				t.Fatalf("route %s has no role policy and is not an operational probe", pattern)
			}
			continue
		}
		for _, role := range allRealmRoles {
			err := authorizeRequest(method, roleSet(role), policy.allowedRoles)
			allowed := false
			for _, candidate := range policy.allowedRoles {
				if candidate == role {
					allowed = true
				}
			}
			_, readOnly := readOnlyRoles[role]
			expectDenied := !allowed || (readOnly && isMutating(method))
			if expectDenied && err == nil {
				t.Errorf("role %s must be denied %s", role, pattern)
			}
			if !expectDenied && err != nil {
				t.Errorf("role %s must be allowed %s: %v", role, pattern, err)
			}
		}
		// An unknown role is never authorized.
		if err := authorizeRequest(method, roleSet("unapproved-role"), policy.allowedRoles); !errors.Is(err, errRoleNotAllowed) {
			t.Errorf("unknown role must be denied %s, got %v", pattern, err)
		}
	}
}

// TestReadOnlyRolesDeniedAllMutatingEndpoints proves the generic guard: an
// oversight role is denied on every non-read method even where the route
// table would list it (it never should for mutating routes).
func TestReadOnlyRolesDeniedAllMutatingEndpoints(t *testing.T) {
	for role := range readOnlyRoles {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			if err := authorizeRequest(method, roleSet(role), privacyReaderRoles); err == nil {
				t.Errorf("read-only role %s must be denied %s even on reader routes", role, method)
			}
		}
	}
}

// TestAuthorizeRequestDeniesMissingRoleClaim is the fail-closed missing-claim
// case: no roles at all must be a denial, distinct from a wrong role.
func TestAuthorizeRequestDeniesMissingRoleClaim(t *testing.T) {
	if err := authorizeRequest(http.MethodGet, nil, privacyReaderRoles); !errors.Is(err, errRoleClaimMissing) {
		t.Fatalf("expected missing-claim denial, got %v", err)
	}
	if err := authorizeRequest(http.MethodPost, map[string]struct{}{}, onboardingOperatorRoles); !errors.Is(err, errRoleClaimMissing) {
		t.Fatalf("expected missing-claim denial, got %v", err)
	}
}

type stubAuthenticator struct {
	identity AuthenticatedIdentity
	err      error
}

func (stub stubAuthenticator) Authenticate(*http.Request) (AuthenticatedIdentity, error) {
	return stub.identity, stub.err
}

func newStubService(roles ...string) *HTTPService {
	return &HTTPService{
		authenticator: stubAuthenticator{identity: AuthenticatedIdentity{Subject: "stub-subject", Roles: roleSet(roles...)}},
	}
}

// TestUnknownRouteIsDenied proves the default-deny wrapper: paths outside the
// policy table receive 403, not a pass-through or an unauthenticated 404.
func TestUnknownRouteIsDenied(t *testing.T) {
	handler := newStubService(RolePlatformAdmin).Handler()
	for _, path := range []string{"/v1/unknown", "/v1/onboarding", "/admin"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("unknown route %s must be 403, got %d", path, recorder.Code)
		}
	}
}

func TestHealthProbeIsUnauthenticated(t *testing.T) {
	service := &HTTPService{}
	recorder := httptest.NewRecorder()
	service.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("health probe must stay reachable, got %d", recorder.Code)
	}
}

// TestProtectedEndpointRoleEnforcement exercises the middleware end to end:
// observers are 403 on mutating routes, officers pass authorization, and a
// roleless identity is 403 even with a valid credential.
func TestProtectedEndpointRoleEnforcement(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		path       string
		roles      []string
		wantStatus int
	}{
		{"observer denied submit", http.MethodPost, "/v1/onboarding/requests", []string{RoleCBNObserver}, http.StatusForbidden},
		{"auditor denied onboarding decision", http.MethodPost, "/v1/onboarding/requests/abc/decision", []string{RoleIndependentAuditor}, http.StatusForbidden},
		{"icrc observer denied privacy decision", http.MethodPost, "/v1/privacy/activities/abc/decision", []string{RoleICRCObserver}, http.StatusForbidden},
		{"nwa officer denied onboarding decision", http.MethodPost, "/v1/onboarding/requests/abc/decision", []string{RoleNWAOfficer}, http.StatusForbidden},
		{"roleless identity denied", http.MethodPost, "/v1/onboarding/requests", nil, http.StatusForbidden},
		// Allowed roles pass authorization and reach request-body validation.
		{"nimasa officer passes submit authz", http.MethodPost, "/v1/onboarding/requests", []string{RoleNIMASAOfficer}, http.StatusBadRequest},
		{"platform admin passes decision authz", http.MethodPost, "/v1/onboarding/requests/abc/decision", []string{RolePlatformAdmin}, http.StatusBadRequest},
		// Read access for observers on GET routes is covered by the policy
		// matrix test; the read handler itself requires a live store.
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			service := newStubService(testCase.roles...)
			recorder := httptest.NewRecorder()
			service.Handler().ServeHTTP(recorder, httptest.NewRequest(testCase.method, testCase.path, strings.NewReader(`{}`)))
			if recorder.Code != testCase.wantStatus {
				t.Fatalf("got %d, want %d (body: %s)", recorder.Code, testCase.wantStatus, recorder.Body.String())
			}
		})
	}
}

func TestUnauthenticatedRequestIsRejectedBeforeAuthorization(t *testing.T) {
	service := &HTTPService{authenticator: stubAuthenticator{err: errors.New("Bearer authorization is required")}}
	recorder := httptest.NewRecorder()
	service.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/onboarding/requests", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}

// TestTrustedProxyRolesHeader verifies that, in trusted_proxy mode, roles are
// asserted only through the approved header and a missing header yields a
// roleless (therefore denied) identity.
func TestTrustedProxyRolesHeader(t *testing.T) {
	_, network, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	authenticator := trustedProxyAuthenticator{cidrs: []*net.IPNet{network}, identity: "edge-1"}

	request := httptest.NewRequest(http.MethodPost, "/v1/onboarding/requests", nil)
	request.RemoteAddr = "10.1.2.3:8443"
	request.Header.Set("X-Blueeconomy-Authenticated-By", "edge-1")
	request.Header.Set("X-Blueeconomy-Authenticated-Subject", "subject-1")
	request.Header.Set("X-Blueeconomy-Authenticated-Roles", "nimasa-officer, platform-admin")
	identity, err := authenticator.Authenticate(request)
	if err != nil {
		t.Fatalf("trusted proxy identity was rejected: %v", err)
	}
	if identity.Subject != "subject-1" {
		t.Fatalf("unexpected subject %q", identity.Subject)
	}
	if err := authorizeRequest(http.MethodPost, identity.Roles, onboardingApproverRoles); err != nil {
		t.Fatalf("asserted roles must authorize: %v", err)
	}

	request.Header.Del("X-Blueeconomy-Authenticated-Roles")
	identity, err = authenticator.Authenticate(request)
	if err != nil {
		t.Fatalf("missing roles header must not fail authentication: %v", err)
	}
	if err := authorizeRequest(http.MethodPost, identity.Roles, onboardingApproverRoles); !errors.Is(err, errRoleClaimMissing) {
		t.Fatalf("missing roles header must yield missing-claim denial, got %v", err)
	}
}

// --- httptest JWKS integration, mirroring the live Keycloak suite pattern ---

type jwksFixture struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newJWKSFixture(t *testing.T) *jwksFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &jwksFixture{key: key, kid: "test-key-1"}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": fixture.kid,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}},
		})
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *jwksFixture) signToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": fixture.kid, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, fixture.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (fixture *jwksFixture) authenticator(t *testing.T, rolesClientIDs ...string) *oidcAuthenticator {
	t.Helper()
	jwksURL, err := url.Parse(fixture.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &oidcAuthenticator{
		issuer:         "https://keycloak.test/realms/blueeconomy",
		audience:       "admin-service",
		jwksURL:        jwksURL,
		rolesClientIDs: rolesClientIDs,
		client:         fixture.server.Client(),
		keys:           make(map[string]*rsa.PublicKey),
	}
}

func (fixture *jwksFixture) bearerRequest(t *testing.T, path string, claims map[string]any) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer "+fixture.signToken(t, claims))
	return request
}

func validClaims(roles map[string]any) map[string]any {
	claims := map[string]any{
		"iss": "https://keycloak.test/realms/blueeconomy",
		"sub": "keycloak-subject-1",
		"aud": "admin-service",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	for key, value := range roles {
		claims[key] = value
	}
	return claims
}

// TestOIDCRealmAndResourceRolesAuthorize verifies the documented claim
// mapping: realm_access.roles plus resource_access roles for the configured
// client IDs only.
func TestOIDCRealmAndResourceRolesAuthorize(t *testing.T) {
	fixture := newJWKSFixture(t)
	authenticator := fixture.authenticator(t, "admin-service")
	claims := validClaims(map[string]any{
		"realm_access": map[string]any{"roles": []string{"nimasa-officer"}},
		"resource_access": map[string]any{
			"admin-service":    map[string]any{"roles": []string{"platform-admin"}},
			"unrelated-client": map[string]any{"roles": []string{"cbn-observer"}},
		},
	})
	identity, err := authenticator.Authenticate(fixture.bearerRequest(t, "/v1/onboarding/requests", claims))
	if err != nil {
		t.Fatalf("signed token was rejected: %v", err)
	}
	if identity.Subject != "keycloak-subject-1" {
		t.Fatalf("unexpected subject %q", identity.Subject)
	}
	for _, role := range []string{RoleNIMASAOfficer, RolePlatformAdmin} {
		if _, ok := identity.Roles[role]; !ok {
			t.Fatalf("expected role %s in %v", role, identity.Roles)
		}
	}
	if _, ok := identity.Roles[RoleCBNObserver]; ok {
		t.Fatal("roles from an unconfigured client must not be trusted")
	}
	if err := authorizeRequest(http.MethodPost, identity.Roles, onboardingApproverRoles); err != nil {
		t.Fatalf("extracted roles must authorize the approver route: %v", err)
	}
}

// TestOIDCTokenWithoutRoleClaimIsDenied covers the fail-closed missing-claim
// path through the full HTTP stack: a valid signature with no role claims is
// authenticated but receives 403 on every protected route.
func TestOIDCTokenWithoutRoleClaimIsDenied(t *testing.T) {
	fixture := newJWKSFixture(t)
	service := &HTTPService{authenticator: fixture.authenticator(t)}
	token := fixture.signToken(t, validClaims(nil))
	for _, target := range []struct{ method, path string }{
		{http.MethodPost, "/v1/onboarding/requests"},
		{http.MethodPost, "/v1/onboarding/requests/abc/decision"},
		{http.MethodGet, "/v1/privacy/activities/abc"},
	} {
		request := httptest.NewRequest(target.method, target.path, strings.NewReader(`{}`))
		request.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		service.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%s %s with no role claim must be 403, got %d", target.method, target.path, recorder.Code)
		}
	}
}

// TestOIDCObserverTokenDeniedMutation proves a signed token carrying only a
// read-only oversight role cannot reach any mutating endpoint.
func TestOIDCObserverTokenDeniedMutation(t *testing.T) {
	fixture := newJWKSFixture(t)
	service := &HTTPService{authenticator: fixture.authenticator(t)}
	token := fixture.signToken(t, validClaims(map[string]any{
		"realm_access": map[string]any{"roles": []string{"icrc-observer"}},
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/onboarding/requests", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	service.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("observer mutation must be 403, got %d", recorder.Code)
	}
	if got := fmt.Sprint(recorder.Body.String()); !strings.Contains(got, "role") {
		t.Fatalf("denial should reference role authorization, got %s", got)
	}
}

func TestNormalizeRolesBoundsAndCanonicalizes(t *testing.T) {
	roles := normalizeRoles([]string{" platform-admin ", "", strings.Repeat("a", 200), "nimasa-officer"})
	if len(roles) != 2 {
		t.Fatalf("expected two canonical roles, got %v", roles)
	}
	oversized := make([]string, 0, 128)
	for index := 0; index < 128; index++ {
		oversized = append(oversized, fmt.Sprintf("role-%d", index))
	}
	if got := len(normalizeRoles(oversized)); got != 64 {
		t.Fatalf("role claim cardinality must be capped at 64, got %d", got)
	}
}
