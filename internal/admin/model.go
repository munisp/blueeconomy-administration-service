package admin

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

type RequestStatus string

const (
	StatusSubmitted          RequestStatus = "submitted"
	StatusApproved           RequestStatus = "approved"
	StatusRejected           RequestStatus = "rejected"
	StatusInvited            RequestStatus = "invited"
	StatusActivating         RequestStatus = "activating"
	StatusActivationFailed   RequestStatus = "activation_failed"
	StatusActive             RequestStatus = "active"
	StatusProvisioningFailed RequestStatus = "provisioning_failed"
)

type OnboardingRequest struct {
	ID               string        `json:"id"`
	OrganizationID   string        `json:"organization_id"`
	Email            string        `json:"email"`
	FirstName        string        `json:"first_name"`
	LastName         string        `json:"last_name"`
	RequestedRoles   []string      `json:"requested_roles"`
	RequesterSubject string        `json:"requester_subject"`
	Status           RequestStatus `json:"status"`
	CreatedAt        time.Time     `json:"created_at"`
	UpdatedAt        time.Time     `json:"updated_at"`
}

type SubmitInput struct {
	OrganizationID string   `json:"organization_id"`
	Email          string   `json:"email"`
	FirstName      string   `json:"first_name"`
	LastName       string   `json:"last_name"`
	RequestedRoles []string `json:"requested_roles"`
}

func (input SubmitInput) Validate(expectedOrganizationID string, allowedRoles map[string]struct{}) error {
	if strings.TrimSpace(input.OrganizationID) == "" || input.OrganizationID != expectedOrganizationID {
		return errors.New("organization_id is not an approved onboarding organization")
	}
	address, err := mail.ParseAddress(strings.TrimSpace(input.Email))
	if err != nil || address.Address != input.Email || len(input.Email) > 320 {
		return errors.New("email must be an approved canonical e-mail address")
	}
	for _, field := range []struct{ name, value string }{{"first_name", input.FirstName}, {"last_name", input.LastName}} {
		if value := strings.TrimSpace(field.value); value == "" || len(value) > 255 {
			return fmt.Errorf("%s must be non-empty and at most 255 characters", field.name)
		}
	}
	if len(input.RequestedRoles) == 0 {
		return errors.New("requested_roles must not be empty")
	}
	seen := make(map[string]struct{}, len(input.RequestedRoles))
	for _, role := range input.RequestedRoles {
		role = strings.TrimSpace(role)
		if _, allowed := allowedRoles[role]; !allowed {
			return fmt.Errorf("requested role %q is not in the approved role catalogue", role)
		}
		if _, duplicate := seen[role]; duplicate {
			return fmt.Errorf("requested role %q is duplicated", role)
		}
		seen[role] = struct{}{}
	}
	return nil
}

func CanApprove(requesterSubject, approverSubject string) error {
	if strings.TrimSpace(requesterSubject) == "" || strings.TrimSpace(approverSubject) == "" {
		return errors.New("requester and approver subjects are required")
	}
	if requesterSubject == approverSubject {
		return errors.New("maker/checker violation: requester cannot approve their own onboarding request")
	}
	return nil
}
