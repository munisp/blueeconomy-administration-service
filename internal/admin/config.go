package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	KeycloakCAFile            string
	ServiceActorSubject       string
	AllowedRoles              map[string]struct{}
	RoleGroupIDs              map[string]string
	AuthMode                  string
	OIDCIssuer                string
	OIDCAudience              string
	OIDCJWKSURL               *url.URL
	OIDCCAFile                string
	TrustedProxyIdentity      string
	TrustedProxyCIDRs         []*net.IPNet
}

func LoadConfig() (Config, error) {
	config := Config{
		ListenAddress:             strings.TrimSpace(os.Getenv("ADMIN_SERVICE_LISTEN_ADDRESS")),
		PostgresDSN:               strings.TrimSpace(os.Getenv("ADMIN_SERVICE_POSTGRES_DSN")),
		KeycloakRealm:             strings.TrimSpace(os.Getenv("KEYCLOAK_REALM")),
		KeycloakOrganizationID:    strings.TrimSpace(os.Getenv("KEYCLOAK_ORGANIZATION_ID")),
		KeycloakAdminClientID:     strings.TrimSpace(os.Getenv("KEYCLOAK_ADMIN_CLIENT_ID")),
		KeycloakAdminClientSecret: strings.TrimSpace(os.Getenv("KEYCLOAK_ADMIN_CLIENT_SECRET")),
		KeycloakCAFile:            strings.TrimSpace(os.Getenv("KEYCLOAK_CA_FILE")),
		ServiceActorSubject:       strings.TrimSpace(os.Getenv("KEYCLOAK_SERVICE_ACTOR_SUBJECT")),
		AllowedRoles:              make(map[string]struct{}),
		RoleGroupIDs:              make(map[string]string),
		AuthMode:                  strings.TrimSpace(os.Getenv("ADMIN_AUTH_MODE")),
		OIDCIssuer:                strings.TrimSpace(os.Getenv("ADMIN_OIDC_ISSUER")),
		OIDCAudience:              strings.TrimSpace(os.Getenv("ADMIN_OIDC_AUDIENCE")),
		OIDCCAFile:                strings.TrimSpace(os.Getenv("ADMIN_OIDC_CA_FILE")),
		TrustedProxyIdentity:      strings.TrimSpace(os.Getenv("ADMIN_TRUSTED_PROXY_IDENTITY")),
	}
	if config.ListenAddress == "" {
		return Config{}, errors.New("ADMIN_SERVICE_LISTEN_ADDRESS is required")
	}
	if config.PostgresDSN == "" {
		return Config{}, errors.New("ADMIN_SERVICE_POSTGRES_DSN is required")
	}
	if config.AuthMode == "" {
		return Config{}, errors.New("ADMIN_AUTH_MODE is required and must be jwt or trusted_proxy")
	}
	var err error
	switch config.AuthMode {
	case "jwt":
		if config.OIDCIssuer == "" || config.OIDCAudience == "" {
			return Config{}, errors.New("ADMIN_OIDC_ISSUER and ADMIN_OIDC_AUDIENCE are required in jwt mode")
		}
		if config.OIDCJWKSURL, err = parseHTTPSURL("ADMIN_OIDC_JWKS_URL"); err != nil {
			return Config{}, err
		}
	case "trusted_proxy":
		if config.TrustedProxyIdentity == "" {
			return Config{}, errors.New("ADMIN_TRUSTED_PROXY_IDENTITY is required in trusted_proxy mode")
		}
		config.TrustedProxyCIDRs, err = parseCIDRs(os.Getenv("ADMIN_TRUSTED_PROXY_CIDRS"))
		if err != nil {
			return Config{}, err
		}
	default:
		return Config{}, errors.New("ADMIN_AUTH_MODE must be jwt or trusted_proxy")
	}
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
	mapping := strings.TrimSpace(os.Getenv("KEYCLOAK_ROLE_GROUP_MAPPING_JSON"))
	if mapping == "" {
		return Config{}, errors.New("KEYCLOAK_ROLE_GROUP_MAPPING_JSON is required")
	}
	if err := json.Unmarshal([]byte(mapping), &config.RoleGroupIDs); err != nil {
		return Config{}, fmt.Errorf("parse KEYCLOAK_ROLE_GROUP_MAPPING_JSON: %w", err)
	}
	for role := range config.AllowedRoles {
		groupID := strings.TrimSpace(config.RoleGroupIDs[role])
		if groupID == "" {
			return Config{}, fmt.Errorf("role %q has no approved Keycloak group mapping", role)
		}
		config.RoleGroupIDs[role] = groupID
	}
	return config, nil
}

func parseCIDRs(value string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, raw := range strings.Split(strings.TrimSpace(value), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("parse ADMIN_TRUSTED_PROXY_CIDRS entry %q: %w", raw, err)
		}
		networks = append(networks, network)
	}
	if len(networks) == 0 {
		return nil, errors.New("ADMIN_TRUSTED_PROXY_CIDRS must contain one or more networks")
	}
	return networks, nil
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
