package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPService struct {
	store          *Store
	keycloak       *KeycloakClient
	organizationID string
	allowedRoles   map[string]struct{}
	serviceActor   string
}

func NewHTTPService(store *Store, keycloak *KeycloakClient, config Config) *HTTPService {
	return &HTTPService{
		store:          store,
		keycloak:       keycloak,
		organizationID: config.KeycloakOrganizationID,
		allowedRoles:   config.AllowedRoles,
		serviceActor:   config.ServiceActorSubject,
	}
}

func (service *HTTPService) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", service.health)
	mux.HandleFunc("POST /v1/onboarding/requests", service.submit)
	mux.HandleFunc("POST /v1/onboarding/requests/{id}/decision", service.decide)
	mux.HandleFunc("POST /v1/onboarding/requests/{id}/provision", service.provision)
	mux.HandleFunc("POST /v1/onboarding/requests/{id}/activate", service.activate)
	return securityHeaders(mux)
}

func (service *HTTPService) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (service *HTTPService) submit(writer http.ResponseWriter, request *http.Request) {
	subject, err := authenticatedSubject(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err)
		return
	}
	var input SubmitInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return
	}
	input.OrganizationID = strings.TrimSpace(input.OrganizationID)
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
	approver, err := authenticatedSubject(request)
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
		if strings.Contains(err.Error(), "maker/checker") {
			writeError(writer, http.StatusForbidden, err)
			return
		}
		writeError(writer, http.StatusConflict, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (service *HTTPService) activate(writer http.ResponseWriter, request *http.Request) {
	if _, err := authenticatedSubject(request); err != nil {
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
	candidate, err := service.store.ClaimActivation(request.Context(), request.PathValue("id"))
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
	if _, err := authenticatedSubject(request); err != nil {
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

func authenticatedSubject(request *http.Request) (string, error) {
	subject := strings.TrimSpace(request.Header.Get("X-Blueeconomy-Authenticated-Subject"))
	if subject == "" || len(subject) > 512 {
		return "", errors.New("API-edge authenticated subject is required")
	}
	return subject, nil
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
