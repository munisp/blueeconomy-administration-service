package admin

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type subjectAuthenticator interface {
	Subject(*http.Request) (string, error)
}

type trustedProxyAuthenticator struct {
	cidrs    []*net.IPNet
	identity string
}

func (auth trustedProxyAuthenticator) Subject(request *http.Request) (string, error) {
	remoteHost, _, err := net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
	if err != nil {
		remoteHost = strings.TrimSpace(request.RemoteAddr)
	}
	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil {
		return "", errors.New("trusted proxy source address is invalid")
	}
	allowed := false
	for _, network := range auth.cidrs {
		if network.Contains(remoteIP) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", errors.New("request source is not an approved trusted proxy")
	}
	if strings.TrimSpace(request.Header.Get("X-Blueeconomy-Authenticated-By")) != auth.identity {
		return "", errors.New("trusted proxy identity is missing or invalid")
	}
	return validatedSubject(request.Header.Get("X-Blueeconomy-Authenticated-Subject"))
}

type oidcAuthenticator struct {
	issuer   string
	audience string
	jwksURL  *url.URL
	client   *http.Client
	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey
	loadedAt time.Time
}

func newOIDCAuthenticator(config Config) *oidcAuthenticator {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if config.OIDCCAFile != "" {
		pemBytes, err := os.ReadFile(config.OIDCCAFile)
		if err == nil {
			pool, poolErr := x509.SystemCertPool()
			if poolErr != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if pool.AppendCertsFromPEM(pemBytes) {
				transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
			}
		}
	}
	return &oidcAuthenticator{
		issuer:   config.OIDCIssuer,
		audience: config.OIDCAudience,
		jwksURL:  config.OIDCJWKSURL,
		client:   &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("JWKS redirects are not permitted") }},
		keys:     make(map[string]*rsa.PublicKey),
	}
}

func (auth *oidcAuthenticator) Subject(request *http.Request) (string, error) {
	value := strings.TrimSpace(request.Header.Get("Authorization"))
	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", errors.New("Bearer authorization is required")
	}
	token := strings.TrimSpace(parts[1])
	segments := strings.Split(token, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return "", errors.New("JWT compact serialization is invalid")
	}
	headerBytes, err := decodeBase64URL(segments[0])
	if err != nil {
		return "", errors.New("JWT header is invalid")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != "RS256" || strings.TrimSpace(header.Kid) == "" {
		return "", errors.New("JWT algorithm or key ID is invalid")
	}
	key, err := auth.key(header.Kid, true)
	if err != nil {
		return "", err
	}
	signature, err := decodeBase64URL(segments[2])
	if err != nil {
		return "", errors.New("JWT signature is invalid")
	}
	digest := sha256.Sum256([]byte(segments[0] + "." + segments[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return "", errors.New("JWT signature verification failed")
	}
	payloadBytes, err := decodeBase64URL(segments[1])
	if err != nil {
		return "", errors.New("JWT claims are invalid")
	}
	var claims struct {
		Issuer    string          `json:"iss"`
		Subject   string          `json:"sub"`
		Audience  json.RawMessage `json:"aud"`
		Expires   json.Number     `json:"exp"`
		NotBefore json.Number     `json:"nbf"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil {
		return "", errors.New("JWT claims are invalid")
	}
	if claims.Issuer != auth.issuer || !audienceContains(claims.Audience, auth.audience) {
		return "", errors.New("JWT issuer or audience is invalid")
	}
	now := time.Now().Unix()
	expires, err := claims.Expires.Int64()
	if err != nil || now >= expires {
		return "", errors.New("JWT is expired or has no valid expiry")
	}
	if claims.NotBefore != "" {
		notBefore, parseErr := claims.NotBefore.Int64()
		if parseErr != nil || now < notBefore {
			return "", errors.New("JWT is not yet valid")
		}
	}
	return validatedSubject(claims.Subject)
}

func (auth *oidcAuthenticator) key(kid string, refresh bool) (*rsa.PublicKey, error) {
	auth.mu.RLock()
	key := auth.keys[kid]
	fresh := time.Since(auth.loadedAt) < 5*time.Minute
	auth.mu.RUnlock()
	if key != nil && fresh {
		return key, nil
	}
	if !refresh {
		return nil, errors.New("JWT key is not trusted")
	}
	if err := auth.loadKeys(); err != nil {
		return nil, fmt.Errorf("load OIDC JWKS: %w", err)
	}
	auth.mu.RLock()
	defer auth.mu.RUnlock()
	if key := auth.keys[kid]; key != nil {
		return key, nil
	}
	return nil, errors.New("JWT key ID is not trusted")
}

func (auth *oidcAuthenticator) loadKeys() error {
	request, err := http.NewRequest(http.MethodGet, auth.jwksURL.String(), nil)
	if err != nil {
		return err
	}
	response, err := auth.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	var document struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return err
	}
	loaded := make(map[string]*rsa.PublicKey)
	for _, item := range document.Keys {
		if item.Kty != "RSA" || item.Use != "sig" || item.Alg != "RS256" || item.Kid == "" || item.N == "" || item.E == "" {
			continue
		}
		modulus, err := decodeBase64URL(item.N)
		if err != nil {
			continue
		}
		exponentBytes, err := decodeBase64URL(item.E)
		if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
			continue
		}
		exponent := 0
		for _, value := range exponentBytes {
			exponent = exponent<<8 | int(value)
		}
		if exponent < 3 || exponent%2 == 0 {
			continue
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}
		if key.N.BitLen() < 2048 {
			continue
		}
		loaded[item.Kid] = key
	}
	if len(loaded) == 0 {
		return errors.New("JWKS contains no approved RSA signing keys")
	}
	auth.mu.Lock()
	auth.keys = loaded
	auth.loadedAt = time.Now()
	auth.mu.Unlock()
	return nil
}

func decodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func audienceContains(raw json.RawMessage, expected string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == expected
	}
	var multiple []string
	if json.Unmarshal(raw, &multiple) != nil {
		return false
	}
	for _, value := range multiple {
		if value == expected {
			return true
		}
	}
	return false
}

func validatedSubject(value string) (string, error) {
	subject := strings.TrimSpace(value)
	if subject == "" || len(subject) > 512 {
		return "", errors.New("authenticated subject is required")
	}
	return subject, nil
}
