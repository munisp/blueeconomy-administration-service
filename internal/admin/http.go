package admin

import (
	"github.com/munisp/blueeconomy-administration-service/internal/pbac"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type HTTPService struct {
	store               *Store
	keycloak            *KeycloakClient
	organizationID      string
	allowedRoles        map[string]struct{}
	serviceActor        string
	authenticator       subjectAuthenticator
	rateLimiter         enrollmentRateLimiter
	enrollmentRateLimit int
	// pbac is the embedded-OPA authorization gate on privileged routes;
	// tenantLookup resolves resource tenants for policy evaluation.
	pbac         *pbac.Engine
	tenantLookup onboardingTenantLookup
}

// enrollmentRateLimiter is the strict fixed-window limiter guarding the
// public self-service endpoint. *Store implements it against PostgreSQL.
type enrollmentRateLimiter interface {
	AllowEnrollmentRequest(ctx context.Context, bucketKey string, windowStart time.Time, limit int) (bool, error)
}

func NewHTTPService(store *Store, keycloak *KeycloakClient, config Config) *HTTPService {
	return &HTTPService{
		store:               store,
		keycloak:            keycloak,
		organizationID:      config.KeycloakOrganizationID,
		allowedRoles:        config.AllowedRoles,
		serviceActor:        config.ServiceActorSubject,
		authenticator:       newSubjectAuthenticator(config),
		rateLimiter:         store,
		enrollmentRateLimit: config.EnrollmentRateLimitPerMinute,
		tenantLookup:        store,
	}
}

// SetPBACEngine attaches the embedded-OPA authorization engine. Privileged
// routes deny every request until an engine is attached (fail-closed).
func (service *HTTPService) SetPBACEngine(engine *pbac.Engine) {
	service.pbac = engine
}

func (service *HTTPService) Handler() http.Handler {
	mux := http.NewServeMux()
	for pattern, policy := range service.routes() {
		if len(policy.allowedRoles) == 0 {
			mux.HandleFunc(pattern, policy.handler)
			continue
		}
		handler := policy.handler
		if policy.pbacAction != "" {
			if policy.pbacCollection {
				handler = service.requirePBACCollection(policy.pbacAction, "onboarding_request", handler)
			} else {
				handler = service.requirePBAC(policy.pbacAction, handler)
			}
		}
		mux.HandleFunc(pattern, service.requireRoles(policy.allowedRoles, handler))
	}
	return securityHeaders(service.defaultDeny(mux))
}

func (service *HTTPService) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (service *HTTPService) submit(writer http.ResponseWriter, request *http.Request) {
	subject, err := service.authenticatedSubject(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	var input SubmitInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	input = input.Normalize()
	if err := input.Validate(service.organizationID, service.allowedRoles); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	created, err := service.store.Create(request.Context(), input, subject)
	if err != nil {
		writeError(writer, http.StatusConflict, errors.New("onboarding request could not be recorded"))
		return
	}
	writeJSON(writer, http.StatusCreated, created)
}

func (service *HTTPService) decide(writer http.ResponseWriter, request *http.Request) {
	approver, err := service.authenticatedSubject(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	var input struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	if input.Decision != "approve" && input.Decision != "reject" {
		writeError(writer, http.StatusBadRequest, errors.New("decision must be approve or reject"))
		return
	}
	result, err := service.store.Decide(request.Context(), request.PathValue("id"), approver, input.Decision, strings.TrimSpace(input.Reason))
	if err != nil {
		if errors.Is(err, ErrMakerCheckerViolation) {
			writeError(writer, http.StatusForbidden, err)
			return
		}
		writeError(writer, http.StatusConflict, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (service *HTTPService) createPrivacyActivity(writer http.ResponseWriter, request *http.Request) {
	requester, err := service.authenticatedSubject(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	var input CreatePrivacyActivityInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	activity, err := service.store.CreatePrivacyActivity(request.Context(), input, requester)
	if err != nil {
		writeError(writer, http.StatusConflict, errors.New("privacy activity could not be recorded"))
		return
	}
	writeJSON(writer, http.StatusCreated, activity)
}

func (service *HTTPService) getPrivacyActivity(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authenticatedSubject(request); err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	activity, err := service.store.GetPrivacyActivity(request.Context(), request.PathValue("id"))
	if err != nil {
		writeError(writer, http.StatusNotFound, errors.New("privacy activity was not found"))
		return
	}
	writeJSON(writer, http.StatusOK, activity)
}

func (service *HTTPService) attestPrivacyActivity(writer http.ResponseWriter, request *http.Request) {
	actor, err := service.authenticatedSubject(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	var input PrivacyWorkflowInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	activity, err := service.store.AttestPrivacyActivity(request.Context(), request.PathValue("id"), actor, input)
	if err != nil {
		if errors.Is(err, ErrPrivacyActorNotOwner) {
			writeError(writer, http.StatusForbidden, err)
			return
		}
		writeError(writer, http.StatusConflict, err)
		return
	}
	writeJSON(writer, http.StatusOK, activity)
}

func (service *HTTPService) submitPrivacyDPOReview(writer http.ResponseWriter, request *http.Request) {
	actor, err := service.authenticatedSubject(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	var input PrivacyWorkflowInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	activity, err := service.store.SubmitPrivacyDPOReview(request.Context(), request.PathValue("id"), actor, input)
	if err != nil {
		if errors.Is(err, ErrPrivacyActorNotOwner) {
			writeError(writer, http.StatusForbidden, err)
			return
		}
		writeError(writer, http.StatusConflict, err)
		return
	}
	writeJSON(writer, http.StatusOK, activity)
}

func (service *HTTPService) decidePrivacyActivity(writer http.ResponseWriter, request *http.Request) {
	actor, err := service.authenticatedSubject(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	var input PrivacyDecisionInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	activity, err := service.store.DecidePrivacyActivity(request.Context(), request.PathValue("id"), actor, input)
	if err != nil {
		if errors.Is(err, ErrMakerCheckerViolation) {
			writeError(writer, http.StatusForbidden, err)
			return
		}
		writeError(writer, http.StatusConflict, err)
		return
	}
	writeJSON(writer, http.StatusOK, activity)
}

func (service *HTTPService) activate(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authenticatedSubject(request); err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	var input struct {
		KeycloakUserID string `json:"keycloak_user_id"`
	}
	if err := decodeJSON(request, &input); err != nil || strings.TrimSpace(input.KeycloakUserID) == "" || len(input.KeycloakUserID) > 512 {
		writeError(writer, http.StatusBadRequest, errors.New("a Keycloak user ID is required for activation"))
		return
	}
	candidate, err := service.store.ClaimActivation(request.Context(), request.PathValue("id"), strings.TrimSpace(input.KeycloakUserID))
	if err != nil {
		writeError(writer, http.StatusConflict, err)
		return
	}
	contextWithTimeout, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	if err := service.keycloak.AssignApprovedRoleGroups(contextWithTimeout, strings.TrimSpace(input.KeycloakUserID), candidate.RequestedRoles); err != nil {
		_ = service.store.RecordActivationResult(request.Context(), candidate.ID, service.serviceActor, false, "Keycloak organization group assignment failed")
		writeError(writer, http.StatusBadGateway, errors.New("Keycloak role activation did not complete"))
		return
	}
	if err := service.store.RecordActivationResult(request.Context(), candidate.ID, service.serviceActor, true, "Keycloak organization group assignment completed"); err != nil {
		writeError(writer, http.StatusInternalServerError, errors.New("role activation completed but evidence update failed; investigate immediately"))
		return
	}
	writeJSON(writer, http.StatusNoContent, nil)
}

func (service *HTTPService) provision(writer http.ResponseWriter, request *http.Request) {
	if _, err := service.authenticatedSubject(request); err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	candidate, err := service.store.ClaimProvisioning(request.Context(), request.PathValue("id"))
	if err != nil {
		writeError(writer, http.StatusConflict, err)
		return
	}

	contextWithTimeout, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	err = service.keycloak.InviteUser(contextWithTimeout, candidate)
	if err != nil {
		_ = service.store.RecordProvisioningResult(request.Context(), candidate.ID, service.serviceActor, false, "Keycloak invitation failed")
		writeError(writer, http.StatusBadGateway, errors.New("Keycloak invitation did not complete"))
		return
	}
	if err := service.store.RecordProvisioningResult(request.Context(), candidate.ID, service.serviceActor, true, "Keycloak invitation completed"); err != nil {
		writeError(writer, http.StatusInternalServerError, errors.New("invitation completed but evidence update failed; investigate immediately"))
		return
	}
	writeJSON(writer, http.StatusNoContent, nil)
}

func newSubjectAuthenticator(config Config) subjectAuthenticator {
	if config.AuthMode == "jwt" {
		return newOIDCAuthenticator(config)
	}
	return trustedProxyAuthenticator{cidrs: config.TrustedProxyCIDRs, identity: config.TrustedProxyIdentity}
}

func (service *HTTPService) authenticatedSubject(request *http.Request) (string, error) {
	identity, err := service.identity(request)
	if err != nil {
		return "", err
	}
	return identity.Subject, nil
}

func decodeJSON(request *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("request body is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if payload != nil {
		_ = json.NewEncoder(writer).Encode(payload)
	}
}

func writeError(writer http.ResponseWriter, status int, err error) {
	writeJSON(writer, status, map[string]string{"error": err.Error()})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}

// submitEnrollment is the public self-service enrollment endpoint. It is
// fail-closed on its rate limit: when the limiter is not configured or
// storage is unavailable the request is denied rather than admitted.
func (service *HTTPService) submitEnrollment(writer http.ResponseWriter, request *http.Request) {
	if service.rateLimiter == nil || service.enrollmentRateLimit <= 0 {
		writeError(writer, http.StatusServiceUnavailable, errors.New("self-service enrollment is not enabled"))
		return
	}
	allowed, err := service.rateLimiter.AllowEnrollmentRequest(request.Context(), service.enrollmentRateLimitKey(request), time.Now().UTC().Truncate(time.Minute), service.enrollmentRateLimit)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, errors.New("enrollment rate limiting is unavailable"))
		return
	}
	if !allowed {
		writeError(writer, http.StatusTooManyRequests, errors.New("enrollment request rate limit exceeded"))
		return
	}
	var input EnrollmentSubmitInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	created, err := service.store.CreateEnrollment(request.Context(), service.organizationID, input, SelfServiceRequesterSubject)
	if err != nil {
		writeError(writer, http.StatusConflict, errors.New("enrollment request could not be recorded"))
		return
	}
	writeJSON(writer, http.StatusCreated, created)
}

// enrollmentRateLimitKey scopes the fixed window to the authenticated subject
// when the API edge asserted one, and otherwise to the client IP.
func (service *HTTPService) enrollmentRateLimitKey(request *http.Request) string {
	if identity, err := service.identity(request); err == nil && identity.Subject != "" {
		return "subject:" + identity.Subject
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
	if err != nil || host == "" {
		return "ip:unknown"
	}
	return "ip:" + host
}

func (service *HTTPService) startIdentityReview(writer http.ResponseWriter, request *http.Request) {
	officer, err := service.authenticatedSubject(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	updated, err := service.store.StartIdentityReview(request.Context(), request.PathValue("id"), officer)
	if err != nil {
		writeError(writer, http.StatusConflict, err)
		return
	}
	writeJSON(writer, http.StatusOK, updated)
}

func (service *HTTPService) recordIdentityVerification(writer http.ResponseWriter, request *http.Request) {
	officer, err := service.authenticatedSubject(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	var input IdentityVerificationInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	updated, err := service.store.RecordIdentityVerification(request.Context(), request.PathValue("id"), officer, input)
	if err != nil {
		writeError(writer, http.StatusConflict, err)
		return
	}
	writeJSON(writer, http.StatusOK, updated)
}

func (service *HTTPService) createEnrollmentBatch(writer http.ResponseWriter, request *http.Request) {
	proposer, err := service.authenticatedSubject(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	var input EnrollmentBatchInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	results := ValidateEnrollmentRows(input.Rows)
	batch, records, err := service.store.CreateBatch(request.Context(), proposer, input.Rows, results)
	if err != nil {
		writeError(writer, http.StatusConflict, errors.New("enrollment batch could not be recorded"))
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"batch": batch, "rows": records})
}

func (service *HTTPService) confirmEnrollmentBatch(writer http.ResponseWriter, request *http.Request) {
	confirmer, err := service.authenticatedSubject(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	batch, records, err := service.store.ConfirmBatch(request.Context(), request.PathValue("id"), service.organizationID, confirmer)
	if err != nil {
		if errors.Is(err, ErrMakerCheckerViolation) {
			writeError(writer, http.StatusForbidden, err)
			return
		}
		writeError(writer, http.StatusConflict, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"batch": batch, "rows": records})
}
