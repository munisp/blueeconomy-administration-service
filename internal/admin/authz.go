package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// Approved Keycloak realm roles recognised by this service. Role membership is
// read from the authenticated token's realm_access.roles claim and, when
// ADMIN_OIDC_ROLES_CLIENT_IDS is configured, from resource_access[client].roles.
// In trusted_proxy mode the approved API edge asserts roles through the
// X-Blueeconomy-Authenticated-Roles header (comma-separated).
const (
	RolePlatformAdmin      = "platform-admin"
	RoleNIMASAOfficer      = "nimasa-officer"
	RoleNWAOfficer         = "nwa-officer"
	RoleNIWAOfficer        = "niwa-officer"
	RoleCBNObserver        = "cbn-observer"
	RoleFMMBEOversight     = "fmmbe-oversight"
	RoleIndependentAuditor = "independent-auditor"
	RoleICRCObserver       = "icrc-observer"
)

// readOnlyRoles are oversight roles that must never perform a state transition.
// The authorizer denies them every mutating endpoint generically, independent
// of the per-route policy table.
var readOnlyRoles = map[string]struct{}{
	RoleCBNObserver:        {},
	RoleFMMBEOversight:     {},
	RoleIndependentAuditor: {},
	RoleICRCObserver:       {},
}

var (
	errRoleClaimMissing = errors.New("authenticated token carries no approved role claim")
	errRoleNotAllowed   = errors.New("authenticated subject lacks an approved role for this route")
)

// routePolicy binds one registered route to its minimal allowed role set. A
// nil allowedRoles slice marks an unauthenticated operational probe; every
// other route requires authentication plus role authorization.
type routePolicy struct {
	handler      http.HandlerFunc
	allowedRoles []string
}

var (
	onboardingOperatorRoles = []string{RolePlatformAdmin, RoleNIMASAOfficer, RoleNWAOfficer, RoleNIWAOfficer}
	onboardingApproverRoles = []string{RolePlatformAdmin, RoleNIMASAOfficer}
	privacyReaderRoles      = []string{
		RolePlatformAdmin, RoleNIMASAOfficer, RoleNWAOfficer, RoleNIWAOfficer,
		RoleCBNObserver, RoleFMMBEOversight, RoleIndependentAuditor, RoleICRCObserver,
	}
)

// routes is the single source of truth for the route table and its
// authorization policy. Any route not present here is denied by default.
func (service *HTTPService) routes() map[string]routePolicy {
	return map[string]routePolicy{
		"GET /healthz":                                       {handler: service.health},
		"POST /v1/onboarding/requests":                       {handler: service.submit, allowedRoles: onboardingOperatorRoles},
		"POST /v1/onboarding/requests/{id}/decision":         {handler: service.decide, allowedRoles: onboardingApproverRoles},
		"POST /v1/onboarding/requests/{id}/provision":        {handler: service.provision, allowedRoles: onboardingApproverRoles},
		"POST /v1/onboarding/requests/{id}/activate":         {handler: service.activate, allowedRoles: onboardingApproverRoles},
		"POST /v1/privacy/activities":                        {handler: service.createPrivacyActivity, allowedRoles: onboardingOperatorRoles},
		"GET /v1/privacy/activities/{id}":                    {handler: service.getPrivacyActivity, allowedRoles: privacyReaderRoles},
		"POST /v1/privacy/activities/{id}/attest":            {handler: service.attestPrivacyActivity, allowedRoles: onboardingOperatorRoles},
		"POST /v1/privacy/activities/{id}/submit-dpo-review": {handler: service.submitPrivacyDPOReview, allowedRoles: onboardingOperatorRoles},
		"POST /v1/privacy/activities/{id}/decision":          {handler: service.decidePrivacyActivity, allowedRoles: onboardingApproverRoles},
	}
}

// authorizeRequest enforces the route policy fail-closed: a subject with no
// role claim is denied, read-only oversight roles are denied every mutating
// method, and at least one held role must appear in the route's allowed set.
func authorizeRequest(method string, heldRoles map[string]struct{}, allowedRoles []string) error {
	if len(heldRoles) == 0 {
		return errRoleClaimMissing
	}
	mutating := method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
	for role := range heldRoles {
		if mutating {
			if _, readOnly := readOnlyRoles[role]; readOnly {
				continue
			}
		}
		for _, allowed := range allowedRoles {
			if role == allowed {
				return nil
			}
		}
	}
	return errRoleNotAllowed
}

type identityContextKey struct{}

func withIdentity(ctx context.Context, identity AuthenticatedIdentity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

// requireRoles authenticates the caller and enforces the route policy before
// the wrapped handler runs. The authenticated identity is stored in the
// request context so handlers do not re-verify the credential.
func (service *HTTPService) requireRoles(allowedRoles []string, next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		identity, err := service.identity(request)
		if err != nil {
			writeError(writer, http.StatusUnauthorized, err)
			return
		}
		if err := authorizeRequest(request.Method, identity.Roles, allowedRoles); err != nil {
			writeError(writer, http.StatusForbidden, err)
			return
		}
		next(writer, request.WithContext(withIdentity(request.Context(), identity)))
	}
}

// defaultDeny rejects every request that does not match a registered route.
// Fail-closed: an unknown route is a 403, never an implicit pass-through.
func (service *HTTPService) defaultDeny(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, pattern := mux.Handler(request); pattern == "" {
			writeError(writer, http.StatusForbidden, errors.New("route is not in the approved policy table"))
			return
		}
		mux.ServeHTTP(writer, request)
	})
}

// identity returns the authenticated identity from the request context when
// the authorization middleware already ran, and otherwise authenticates the
// request directly so a bypassed middleware can never yield access.
func (service *HTTPService) identity(request *http.Request) (AuthenticatedIdentity, error) {
	if identity, ok := request.Context().Value(identityContextKey{}).(AuthenticatedIdentity); ok {
		return identity, nil
	}
	if service.authenticator == nil {
		return AuthenticatedIdentity{}, errors.New("authentication is not configured")
	}
	return service.authenticator.Authenticate(request)
}

func parseRoleHeader(value string) map[string]struct{} {
	return normalizeRoles(strings.Split(value, ","))
}

// normalizeRoles canonicalizes a raw role list, dropping blank and oversized
// entries and capping the claim at a sane cardinality.
func normalizeRoles(raw []string) map[string]struct{} {
	roles := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 128 || len(roles) >= 64 {
			continue
		}
		roles[value] = struct{}{}
	}
	return roles
}
