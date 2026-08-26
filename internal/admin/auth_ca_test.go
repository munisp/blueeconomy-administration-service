package admin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewOIDCAuthenticatorRejectsUnreadableConfiguredCAFile(t *testing.T) {
	_, err := newOIDCAuthenticator(Config{OIDCCAFile: filepath.Join(t.TempDir(), "missing-ca.pem")})
	if err == nil {
		t.Fatal("expected unreadable configured OIDC CA file to fail closed")
	}
}

func TestNewOIDCAuthenticatorRejectsInvalidConfiguredCAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := newOIDCAuthenticator(Config{OIDCCAFile: path})
	if err == nil {
		t.Fatal("expected invalid configured OIDC CA file to fail closed")
	}
}
