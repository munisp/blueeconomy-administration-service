package admin

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	ListenAddress             string
	PostgresDSN               string
	KeycloakTokenURL          *url.URL
	KeycloakAdminBaseURL      *url.URL
	KeycloakRealm             string
	KeycloakOrganizationID    string
	KeycloakAdminClientID     string
	KeycloakAdminClientSecret string
	ServiceActorSubject       string
	AllowedRoles              map[string]struct{}
}

func LoadConfig() (Config, error) {
	config := Config{
		ListenAddress:             strings.TrimSpace(os.Getenv("ADMIN_SERVICE_LISTEN_ADDRESS")),
		PostgresDSN:               strings.TrimSpace(os.Getenv("ADMIN_SERVICE_POSTGRES_DSN")),
		KeycloakRealm:             strings.TrimSpace(os.Getenv("KEYCLOAK_REALM")),
		KeycloakOrganizationID:    strings.TrimSpace(os.Getenv("KEYCLOAK_ORGANIZATION_ID")),
		KeycloakAdminClientID:     strings.TrimSpace(os.Getenv("KEYCLOAK_ADMIN_CLIENT_ID")),
		KeycloakAdminClientSecret: strings.TrimSpace(os.Getenv("KEYCLOAK_ADMIN_CLIENT_SECRET")),
		ServiceActorSubject:       strings.TrimSpace(os.Getenv("KEYCLOAK_SERVICE_ACTOR_SUBJECT")),
		AllowedRoles:              make(map[string]struct{}),
	}
	if config.ListenAddress == "" {
		return Config{}, errors.New("ADMIN_SERVICE_LISTEN_ADDRESS is required")
	}
	if config.PostgresDSN == "" {
		return Config{}, errors.New("ADMIN_SERVICE_POSTGRES_DSN is required")
	}
	var err error
	if config.KeycloakTokenURL, err = parseHTTPSURL("KEYCLOAK_TOKEN_URL"); err != nil {
		return Config{}, err
	}
	if config.KeycloakAdminBaseURL, err = parseHTTPSURL("KEYCLOAK_ADMIN_BASE_URL"); err != nil {
		return Config{}, err
	}
	for _, required := range []struct{ name, value string }{
		{"KEYCLOAK_REALM", config.KeycloakRealm},
		{"KEYCLOAK_ORGANIZATION_ID", config.KeycloakOrganizationID},
		{"KEYCLOAK_ADMIN_CLIENT_ID", config.KeycloakAdminClientID},
		{"KEYCLOAK_ADMIN_CLIENT_SECRET", config.KeycloakAdminClientSecret},
		{"KEYCLOAK_SERVICE_ACTOR_SUBJECT", config.ServiceActorSubject},
	} {
		if required.value == "" {
			return Config{}, fmt.Errorf("%s is required", required.name)
		}
	}
	for _, role := range strings.Split(strings.TrimSpace(os.Getenv("ONBOARDING_ALLOWED_ROLES")), ",") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		config.AllowedRoles[role] = struct{}{}
	}
	if len(config.AllowedRoles) == 0 {
		return Config{}, errors.New("ONBOARDING_ALLOWED_ROLES must contain one or more approved roles")
	}
	return config, nil
}

func parseHTTPSURL(name string) (*url.URL, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must be an HTTPS URL without credentials, query or fragment", name)
	}
	return parsed, nil
}
