package admin

import (
	"context"
	"errors"
	"net/http"

	"github.com/munisp/blueeconomy-administration-service/internal/pbac"
)

// onboardingTenantLookup resolves the tenant (organization) owning one
// onboarding request. *Store implements it against PostgreSQL; tests
// substitute fakes.
type onboardingTenantLookup interface {
	OnboardingRequestTenant(ctx context.Context, id string) (string, error)
}

// requirePBAC enforces the embedded-OPA authorization policy after the
// route role check. The evaluation input is {roles, clearance, tenant_id,
// resource, action, classification} with the resource tenant resolved from
// the authoritative store (never from caller input). Deny-by-default: a
// missing policy engine, an evaluation error, a policy "false", or an
// unresolvable resource tenant denies the request.
func (service *HTTPService) requirePBAC(action string, next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		identity, err := service.identity(request)
		if err != nil {
			writeError(writer, http.StatusUnauthorized, err)
			return
		}
		if service.pbac == nil {
			writeError(writer, http.StatusForbidden, errors.New("authorization policy engine is not configured (fail-closed)"))
			return
		}
		resourceID := request.PathValue("id")
		resourceTenant, err := service.tenantLookup.OnboardingRequestTenant(request.Context(), resourceID)
		if err != nil {
			// Missing and foreign tenants are indistinguishable (404), the
			// platform ownership-hiding convention.
			writeError(writer, http.StatusNotFound, errors.New("onboarding request not found"))
			return
		}
		allowed, err := service.pbac.Allow(request.Context(), pbac.Input{
			Roles:     pbac.SortedRoles(identity.Roles),
			Clearance: identity.Clearance,
			TenantID:  identity.TenantID,
			Resource: pbac.Resource{
				Kind:     "onboarding_request",
				ID:       resourceID,
				TenantID: resourceTenant,
			},
			Action:         action,
			Classification: "CONFIDENTIAL",
		})
		if err != nil || !allowed {
			writeError(writer, http.StatusForbidden, errors.New("authorization policy denied the request"))
			return
		}
		next(writer, request.WithContext(withIdentity(request.Context(), identity)))
	}
}

// collectionResourceID is the policy resource identifier for tenant-scoped
// collection routes (no single-record path value).
const collectionResourceID = "collection"

// requirePBACCollection enforces the embedded-OPA policy on a collection
// route. The policy resource is the caller-tenant collection itself, so the
// tenant_scoped rule still requires a non-empty tenant claim and the caller
// can only ever address their own tenant's collection; per-record isolation
// inside the collection is enforced by the store query. Deny-by-default:
// missing engine, evaluation error or policy "false" denies the request.
func (service *HTTPService) requirePBACCollection(action, kind string, next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		identity, err := service.identity(request)
		if err != nil {
			writeError(writer, http.StatusUnauthorized, err)
			return
		}
		if service.pbac == nil {
			writeError(writer, http.StatusForbidden, errors.New("authorization policy engine is not configured (fail-closed)"))
			return
		}
		allowed, err := service.pbac.Allow(request.Context(), pbac.Input{
			Roles:     pbac.SortedRoles(identity.Roles),
			Clearance: identity.Clearance,
			TenantID:  identity.TenantID,
			Resource: pbac.Resource{
				Kind:     kind,
				ID:       collectionResourceID,
				TenantID: identity.TenantID,
			},
			Action:         action,
			Classification: "CONFIDENTIAL",
		})
		if err != nil || !allowed {
			writeError(writer, http.StatusForbidden, errors.New("authorization policy denied the request"))
			return
		}
		next(writer, request.WithContext(withIdentity(request.Context(), identity)))
	}
}
