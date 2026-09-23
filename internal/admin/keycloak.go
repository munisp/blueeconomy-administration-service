package admin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

type KeycloakClient struct {
	httpClient *http.Client
	// tokenMu/tokenExpiry cache the client-credentials token until
	// exp - tokenRefreshSkew; tokenFlight coalesces concurrent refreshes
	// into a single token-endpoint round-trip (singleflight).
	tokenMu        sync.Mutex
	tokenValue     string
	tokenExpiry    time.Time
	tokenFlight    singleflight.Group
	tokenURL       *url.URL
	adminBaseURL   *url.URL
	realm          string
	organizationID string
	clientID       string
	clientSecret   string
	roleGroupIDs   map[string]string
}

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func NewKeycloakClient(config Config) (*KeycloakClient, error) {
	httpClient, err := newKeycloakHTTPClient(config.KeycloakCAFile)
	if err != nil {
		return nil, err
	}
	return &KeycloakClient{
		httpClient:     httpClient,
		tokenURL:       config.KeycloakTokenURL,
		adminBaseURL:   config.KeycloakAdminBaseURL,
		realm:          config.KeycloakRealm,
		organizationID: config.KeycloakOrganizationID,
		clientID:       config.KeycloakAdminClientID,
		clientSecret:   config.KeycloakAdminClientSecret,
		roleGroupIDs:   config.RoleGroupIDs,
	}, nil
}

func newKeycloakHTTPClient(caFile string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		certificate, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read Keycloak CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(certificate) {
			return nil, errors.New("Keycloak CA file did not contain a usable PEM certificate")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: transport}, nil
}

func (client *KeycloakClient) InviteUser(ctx context.Context, request OnboardingRequest) error {
	token, err := client.clientCredentialsToken(ctx)
	if err != nil {
		return err
	}
	endpoint := client.adminBaseURL.JoinPath("admin", "realms", client.realm, "organizations", client.organizationID, "members", "invite-user")
	form := url.Values{
		"email":     {request.Email},
		"firstName": {request.FirstName},
		"lastName":  {request.LastName},
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create Keycloak invitation request: %w", err)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := client.httpClient.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("send Keycloak invitation request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Keycloak invitation returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (client *KeycloakClient) AssignApprovedRoleGroups(ctx context.Context, keycloakUserID string, roles []string) error {
	if strings.TrimSpace(keycloakUserID) == "" {
		return errors.New("Keycloak user ID is required for group activation")
	}
	token, err := client.clientCredentialsToken(ctx)
	if err != nil {
		return err
	}
	// Bounded-parallel fan-out: one PUT per role/group, at most
	// maxConcurrentGroupPUTs in flight; all errors are aggregated (joined)
	// so a partial failure is honestly reported, never silently dropped.
	group := new(errgroup.Group)
	group.SetLimit(maxConcurrentGroupPUTs)
	errs := make([]error, len(roles))
	for index, role := range roles {
		groupID, exists := client.roleGroupIDs[role]
		if !exists || strings.TrimSpace(groupID) == "" {
			return fmt.Errorf("no approved Keycloak group mapping exists for role %q", role)
		}
		group.Go(func() error {
			endpoint := client.adminBaseURL.JoinPath("admin", "realms", client.realm, "organizations", client.organizationID, "groups", groupID, "members", keycloakUserID)
			request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), nil)
			if err != nil {
				errs[index] = fmt.Errorf("create Keycloak organization group request: %w", err)
				return nil
			}
			request.Header.Set("Authorization", "Bearer "+token)
			response, err := client.httpClient.Do(request)
			if err != nil {
				errs[index] = fmt.Errorf("send Keycloak organization group request: %w", err)
				return nil
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				errs[index] = fmt.Errorf("Keycloak organization group assignment for role %q returned HTTP %d", role, response.StatusCode)
			}
			return nil
		})
	}
	_ = group.Wait()
	return errors.Join(errs...)
}

// tokenRefreshSkew is subtracted from the token lifetime so a cached token
// is never used right up to its expiry boundary.
const tokenRefreshSkew = 30 * time.Second

// maxConcurrentGroupPUTs bounds the parallel organization-group
// assignments in AssignApprovedRoleGroups.
const maxConcurrentGroupPUTs = 4

// clientCredentialsToken returns a cached client-credentials token,
// refreshing it only once it is within tokenRefreshSkew of expiring
// (ExpiresIn was previously parsed but ignored, so every operation paid a
// token-endpoint round-trip). Concurrent refreshes are coalesced via
// singleflight: exactly one token request is in flight at a time.
func (client *KeycloakClient) clientCredentialsToken(ctx context.Context) (string, error) {
	client.tokenMu.Lock()
	if client.tokenValue != "" && time.Now().Before(client.tokenExpiry) {
		token := client.tokenValue
		client.tokenMu.Unlock()
		return token, nil
	}
	client.tokenMu.Unlock()
	result, err, _ := client.tokenFlight.Do("client-credentials", func() (any, error) {
		// Re-check inside the flight: another goroutine may have refreshed
		// the token while this one was queued.
		client.tokenMu.Lock()
		if client.tokenValue != "" && time.Now().Before(client.tokenExpiry) {
			token := client.tokenValue
			client.tokenMu.Unlock()
			return token, nil
		}
		client.tokenMu.Unlock()
		token, expiresIn, err := client.fetchClientCredentialsToken(ctx)
		if err != nil {
			return "", err
		}
		client.tokenMu.Lock()
		client.tokenValue = token
		client.tokenExpiry = time.Now().Add(time.Duration(expiresIn)*time.Second - tokenRefreshSkew)
		client.tokenMu.Unlock()
		return token, nil
	})
	if err != nil {
		return "", err
	}
	return result.(string), nil
}

func (client *KeycloakClient) fetchClientCredentialsToken(ctx context.Context) (string, int, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.clientID},
		"client_secret": {client.clientSecret},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.tokenURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("create Keycloak token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return "", 0, fmt.Errorf("send Keycloak token request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, response.Body)
		return "", 0, fmt.Errorf("Keycloak token endpoint returned HTTP %d", response.StatusCode)
	}
	var payload accessTokenResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return "", 0, fmt.Errorf("decode Keycloak token response: %w", err)
	}
	if payload.TokenType != "Bearer" || strings.TrimSpace(payload.AccessToken) == "" || payload.ExpiresIn <= 0 {
		return "", 0, errors.New("Keycloak token response did not contain a usable bearer access token")
	}
	return payload.AccessToken, payload.ExpiresIn, nil
}
