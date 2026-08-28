package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// List onboarding queue contract. The queue is the approver-facing read model
// over onboarding_requests: it is tenant-scoped to the caller's tenant claim,
// ordered deterministically and paginated with a bounded page size.
const (
	ListDefaultLimit = 25
	ListMaxLimit     = 100
)

// listStatusGroups are the approved logical queue filters. Each group maps to
// the raw lifecycle statuses an approver means when filtering the queue; raw
// internal transition states (provisioning, activating, *_failed,
// *_ambiguous) are visible in the unfiltered queue only.
var listStatusGroups = map[string][]RequestStatus{
	"pending":     {StatusSubmitted, StatusPendingVerification, StatusIdentityReview, StatusIdentityVerified},
	"decided":     {StatusApproved},
	"provisioned": {StatusInvited},
	"active":      {StatusActive},
	"rejected":    {StatusRejected, StatusIdentityRejected},
}

type listFilter struct {
	statuses []RequestStatus
	limit    int
	offset   int
}

// parseListFilter validates the queue query string fail-closed: an unknown
// status group, an out-of-bounds limit or a negative offset is a 400, never a
// silently widened query.
func parseListFilter(query map[string][]string) (listFilter, error) {
	filter := listFilter{limit: ListDefaultLimit}
	values := func(key string) string {
		list := query[key]
		if len(list) == 0 {
			return ""
		}
		return strings.TrimSpace(list[0])
	}
	if status := values("status"); status != "" {
		statuses, known := listStatusGroups[status]
		if !known {
			return listFilter{}, fmt.Errorf("status filter %q is not an approved queue filter (pending, decided, provisioned, active, rejected)", status)
		}
		filter.statuses = statuses
	}
	if raw := values("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > ListMaxLimit {
			return listFilter{}, fmt.Errorf("limit must be an integer between 1 and %d", ListMaxLimit)
		}
		filter.limit = limit
	}
	if raw := values("offset"); raw != "" {
		offset, err := strconv.Atoi(raw)
		if err != nil || offset < 0 {
			return listFilter{}, errors.New("offset must be a non-negative integer")
		}
		filter.offset = offset
	}
	return filter, nil
}

// OnboardingListPage is the pagination envelope: next_offset is null when the
// current page reaches the end of the filtered result set.
type OnboardingListPage struct {
	Limit      int  `json:"limit"`
	Offset     int  `json:"offset"`
	NextOffset *int `json:"next_offset"`
	Total      int  `json:"total"`
}

type OnboardingListResponse struct {
	Requests []OnboardingRequest `json:"requests"`
	Page     OnboardingListPage  `json:"page"`
}

// list serves the tenant-scoped approver queue. Authorization (approver role
// + PBAC tenant scope) runs in middleware before this handler; the handler
// itself still refuses a tenant-less identity so a bypassed middleware can
// never widen the query.
func (service *HTTPService) list(writer http.ResponseWriter, request *http.Request) {
	identity, err := service.identity(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	if identity.TenantID == "" {
		writeError(writer, http.StatusForbidden, errors.New("a tenant claim is required to list onboarding requests"))
		return
	}
	filter, err := parseListFilter(request.URL.Query())
	if err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	requests, total, err := service.store.ListRequests(request.Context(), identity.TenantID, filter.statuses, filter.limit, filter.offset)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, errors.New("onboarding queue could not be read"))
		return
	}
	page := OnboardingListPage{Limit: filter.limit, Offset: filter.offset, Total: total}
	if next := filter.offset + len(requests); next < total {
		page.NextOffset = &next
	}
	if requests == nil {
		requests = []OnboardingRequest{}
	}
	writeJSON(writer, http.StatusOK, OnboardingListResponse{Requests: requests, Page: page})
}

// ListRequests reads one deterministic page of the tenant's onboarding queue,
// oldest first. statuses empty means the unfiltered queue. The total is the
// filtered row count for the tenant, independent of the page window.
func (store *Store) ListRequests(ctx context.Context, organizationID string, statuses []RequestStatus, limit, offset int) ([]OnboardingRequest, int, error) {
	statusValues := make([]string, len(statuses))
	for index, status := range statuses {
		statusValues[index] = string(status)
	}
	const query = `
	SELECT id::text, organization_id, email, first_name, last_name, requested_roles, requester_subject, status, persona,
	       contact_channel, contact_reference, notification_status, created_at, updated_at, count(*) OVER () AS total
	FROM onboarding_requests
	WHERE organization_id = $1
	  AND (cardinality($2::text[]) = 0 OR status::text = ANY($2))
	ORDER BY created_at, id
	LIMIT $3 OFFSET $4`
	rows, err := store.pool.Query(ctx, query, organizationID, statusValues, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list onboarding requests: %w", err)
	}
	defer rows.Close()
	var requests []OnboardingRequest
	total := 0
	for rows.Next() {
		var request OnboardingRequest
		if err := rows.Scan(
			&request.ID,
			&request.OrganizationID,
			&request.Email,
			&request.FirstName,
			&request.LastName,
			&request.RequestedRoles,
			&request.RequesterSubject,
			&request.Status,
			&request.Persona,
			&request.ContactChannel,
			&request.ContactReference,
			&request.NotificationStatus,
			&request.CreatedAt,
			&request.UpdatedAt,
			&total,
		); err != nil {
			return nil, 0, fmt.Errorf("scan onboarding request: %w", err)
		}
		requests = append(requests, request)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate onboarding requests: %w", err)
	}
	return requests, total, nil
}
