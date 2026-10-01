package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type keycloakHarness struct {
	server       *httptest.Server
	tokenCalls   atomic.Int32
	groupCalls   atomic.Int32
	groupLatency time.Duration
}

func newKeycloakHarness(t *testing.T) *keycloakHarness {
	t.Helper()
	harness := &keycloakHarness{}
	harness.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/token":
			harness.tokenCalls.Add(1)
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"access_token": fmt.Sprintf("token-%d", harness.tokenCalls.Load()),
				"token_type":   "Bearer",
				"expires_in":   300,
			})
		case request.Method == http.MethodPut:
			harness.groupCalls.Add(1)
			if strings.Contains(request.URL.Path, "group-bad") {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			if harness.groupLatency > 0 {
				time.Sleep(harness.groupLatency)
			}
			if request.Header.Get("Authorization") == "" {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(harness.server.Close)
	return harness
}

func (harness *keycloakHarness) client(t *testing.T) *KeycloakClient {
	t.Helper()
	tokenURL, err := url.Parse(harness.server.URL + "/token")
	if err != nil {
		t.Fatal(err)
	}
	adminURL, err := url.Parse(harness.server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	return &KeycloakClient{
		httpClient:     harness.server.Client(),
		tokenURL:       tokenURL,
		adminBaseURL:   adminURL,
		realm:          "blueeconomy",
		organizationID: "org-1",
		clientID:       "admin-cli",
		clientSecret:   "secret",
		roleGroupIDs: map[string]string{
			"officer":  "group-officer",
			"reviewer": "group-reviewer",
			"admin":    "group-admin",
		},
	}
}

func TestClientCredentialsTokenCachedAndSingleflight(t *testing.T) {
	harness := newKeycloakHarness(t)
	client := harness.client(t)
	const goroutines = 16
	var wait sync.WaitGroup
	tokens := make([]string, goroutines)
	errs := make([]error, goroutines)
	for i := range goroutines {
		wait.Add(1)
		go func() {
			defer wait.Done()
			token, err := client.clientCredentialsToken(context.Background())
			tokens[i], errs[i] = token, err
		}()
	}
	wait.Wait()
	for i := range goroutines {
		if errs[i] != nil {
			t.Fatalf("token fetch %d: %v", i, errs[i])
		}
		if tokens[i] != "token-1" {
			t.Fatalf("expected cached token-1, got %q", tokens[i])
		}
	}
	if calls := harness.tokenCalls.Load(); calls != 1 {
		t.Fatalf("expected exactly 1 token endpoint call (cache + singleflight), got %d", calls)
	}
}

func TestAssignApprovedRoleGroupsParallelAggregatesErrors(t *testing.T) {
	harness := newKeycloakHarness(t)
	harness.groupLatency = 50 * time.Millisecond
	client := harness.client(t)
	roles := []string{"officer", "reviewer", "admin"}
	start := time.Now()
	if err := client.AssignApprovedRoleGroups(context.Background(), "user-1", roles); err != nil {
		t.Fatalf("assign: %v", err)
	}
	elapsed := time.Since(start)
	if calls := harness.groupCalls.Load(); calls != int32(len(roles)) {
		t.Fatalf("expected %d group PUTs, got %d", len(roles), calls)
	}
	// Serial execution would take >= 3*latency; bounded-parallel must be faster.
	if elapsed >= time.Duration(len(roles))*harness.groupLatency {
		t.Fatalf("group PUTs appear serial: %v >= %v", elapsed, time.Duration(len(roles))*harness.groupLatency)
	}
	if calls := harness.tokenCalls.Load(); calls != 1 {
		t.Fatalf("expected 1 cached token fetch, got %d", calls)
	}
}

func TestAssignApprovedRoleGroupsAggregatesHTTPFailures(t *testing.T) {
	harness := newKeycloakHarness(t)
	client := harness.client(t)
	client.roleGroupIDs["officer"] = "group-bad"
	err := client.AssignApprovedRoleGroups(context.Background(), "user-1", []string{"officer", "reviewer"})
	if err == nil {
		t.Fatal("expected aggregated error for failed group assignment")
	}
	// The successful role still executed (no early abort) — honest partial state.
	if calls := harness.groupCalls.Load(); calls != 2 {
		t.Fatalf("expected both group PUTs to run, got %d calls", calls)
	}
}

func TestAssignApprovedRoleGroupsRejectsUnmappedRole(t *testing.T) {
	harness := newKeycloakHarness(t)
	client := harness.client(t)
	if err := client.AssignApprovedRoleGroups(context.Background(), "user-1", []string{"superuser"}); err == nil {
		t.Fatal("expected error for unmapped role (fail-closed mapping)")
	}
	if calls := harness.groupCalls.Load(); calls != 0 {
		t.Fatalf("no group PUT may run when a role mapping is missing, got %d", calls)
	}
}
