package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
}

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func NewKeycloakClient(config Config) *KeycloakClient {
	return &KeycloakClient{
		httpClient:     &http.Client{Timeout: 15 * time.Second},
		tokenURL:       config.KeycloakTokenURL,
		adminBaseURL:   config.KeycloakAdminBaseURL,
		realm:          config.KeycloakRealm,
		organizationID: config.KeycloakOrganizationID,
		clientID:       config.KeycloakAdminClientID,
		clientSecret:   config.KeycloakAdminClientSecret,
	}
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
