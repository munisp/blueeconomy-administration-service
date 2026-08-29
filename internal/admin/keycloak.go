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
	"time"
)

type KeycloakClient struct {
	httpClient     *http.Client
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

// ErrKeycloakUserNotFound marks a fail-closed identity resolution: no
// enabled Keycloak user exists for the vetted e-mail address, so activation
// must not proceed.
var ErrKeycloakUserNotFound = errors.New("no enabled Keycloak user matches the vetted e-mail address")

// ErrKeycloakUserAmbiguous marks an identity-integrity violation: more than
// one enabled Keycloak user matches the vetted e-mail address. Activation
// fails closed rather than guessing which account receives the roles.
var ErrKeycloakUserAmbiguous = errors.New("multiple enabled Keycloak users match the vetted e-mail address")

type keycloakUserRecord struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Enabled bool   `json:"enabled"`
}

// FindUserIDByEmail resolves the Keycloak user that belongs to one vetted
// e-mail address. The caller must pass the e-mail recorded on the approved
// onboarding request, never client input: this is the server-side binding
// that keeps role-group activation attached to the identity that passed
// vetting. The lookup fails closed when no enabled user matches exactly or
// when the match is ambiguous.
func (client *KeycloakClient) FindUserIDByEmail(ctx context.Context, email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", errors.New("a vetted e-mail address is required to resolve the Keycloak user")
	}
	token, err := client.clientCredentialsToken(ctx)
	if err != nil {
		return "", err
	}
	endpoint := client.adminBaseURL.JoinPath("admin", "realms", client.realm, "users")
	query := endpoint.Query()
	query.Set("email", email)
	query.Set("exact", "true")
	endpoint.RawQuery = query.Encode()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", fmt.Errorf("create Keycloak user lookup request: %w", err)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set("Accept", "application/json")
	response, err := client.httpClient.Do(httpRequest)
	if err != nil {
		return "", fmt.Errorf("send Keycloak user lookup request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, response.Body)
		return "", fmt.Errorf("Keycloak user lookup returned HTTP %d", response.StatusCode)
	}
	var users []keycloakUserRecord
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&users); err != nil {
		return "", fmt.Errorf("decode Keycloak user lookup response: %w", err)
	}
	matched := ""
	for _, user := range users {
		id := strings.TrimSpace(user.ID)
		if !user.Enabled || id == "" {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(user.Email), email) {
			continue
		}
		if matched != "" && matched != id {
			return "", ErrKeycloakUserAmbiguous
		}
		matched = id
	}
	if matched == "" {
		return "", ErrKeycloakUserNotFound
	}
	return matched, nil
}

func (client *KeycloakClient) AssignApprovedRoleGroups(ctx context.Context, keycloakUserID string, roles []string) error {
	if strings.TrimSpace(keycloakUserID) == "" {
		return errors.New("Keycloak user ID is required for group activation")
	}
	token, err := client.clientCredentialsToken(ctx)
	if err != nil {
		return err
	}
	for _, role := range roles {
		groupID, exists := client.roleGroupIDs[role]
		if !exists || strings.TrimSpace(groupID) == "" {
			return fmt.Errorf("no approved Keycloak group mapping exists for role %q", role)
		}
		endpoint := client.adminBaseURL.JoinPath("admin", "realms", client.realm, "organizations", client.organizationID, "groups", groupID, "members", keycloakUserID)
		request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), nil)
		if err != nil {
			return fmt.Errorf("create Keycloak organization group request: %w", err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.httpClient.Do(request)
		if err != nil {
			return fmt.Errorf("send Keycloak organization group request: %w", err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return fmt.Errorf("Keycloak organization group assignment for role %q returned HTTP %d", role, response.StatusCode)
		}
	}
	return nil
}

func (client *KeycloakClient) clientCredentialsToken(ctx context.Context) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.clientID},
		"client_secret": {client.clientSecret},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.tokenURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create Keycloak token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("send Keycloak token request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, response.Body)
		return "", fmt.Errorf("Keycloak token endpoint returned HTTP %d", response.StatusCode)
	}
	var payload accessTokenResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode Keycloak token response: %w", err)
	}
	if payload.TokenType != "Bearer" || strings.TrimSpace(payload.AccessToken) == "" || payload.ExpiresIn <= 0 {
		return "", errors.New("Keycloak token response did not contain a usable bearer access token")
	}
	return payload.AccessToken, nil
}
