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
	StatusSubmitted             RequestStatus = "submitted"
	StatusApproved              RequestStatus = "approved"
	StatusProvisioning          RequestStatus = "provisioning"
	StatusRejected              RequestStatus = "rejected"
	StatusInvited               RequestStatus = "invited"
	StatusActivating            RequestStatus = "activating"
	StatusActivationFailed      RequestStatus = "activation_failed"
	StatusActive                RequestStatus = "active"
	StatusProvisioningFailed    RequestStatus = "provisioning_failed"
	StatusProvisioningAmbiguous RequestStatus = "provisioning_ambiguous"
	StatusActivationAmbiguous   RequestStatus = "activation_ambiguous"
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

func (input SubmitInput) Normalize() SubmitInput {
	normalized := input
	normalized.OrganizationID = strings.TrimSpace(input.OrganizationID)
	normalized.Email = strings.TrimSpace(input.Email)
	normalized.FirstName = strings.TrimSpace(input.FirstName)
	normalized.LastName = strings.TrimSpace(input.LastName)
	normalized.RequestedRoles = make([]string, len(input.RequestedRoles))
	for index, role := range input.RequestedRoles {
		normalized.RequestedRoles[index] = strings.TrimSpace(role)
	}
	return normalized
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

type PrivacyActivityStatus string

const (
	PrivacyActivityDraft                 PrivacyActivityStatus = "draft"
	PrivacyActivityOwnerAttested         PrivacyActivityStatus = "owner_attested"
	PrivacyActivityDPOReview             PrivacyActivityStatus = "dpo_review"
	PrivacyActivityConditionallyApproved PrivacyActivityStatus = "conditionally_approved"
	PrivacyActivityApproved              PrivacyActivityStatus = "approved"
	PrivacyActivityRejected              PrivacyActivityStatus = "rejected"
	PrivacyActivityExpired               PrivacyActivityStatus = "expired"
)

type PrivacyProcessingActivity struct {
	ID                  string                `json:"id"`
	ActivityKey         string                `json:"activity_key"`
	ServiceName         string                `json:"service_name"`
	Purpose             string                `json:"purpose"`
	DataClassifications []string              `json:"data_classifications"`
	ExternalRecipients  []string              `json:"external_recipients"`
	EvidenceSHA256      string                `json:"evidence_sha256"`
	RequesterSubject    string                `json:"requester_subject"`
	OwnerSubject        string                `json:"owner_subject"`
	Status              PrivacyActivityStatus `json:"status"`
	Version             int64                 `json:"version"`
	ApprovalConditions  string                `json:"approval_conditions"`
	ApprovalExpiresAt   *time.Time            `json:"approval_expires_at,omitempty"`
	CreatedAt           time.Time             `json:"created_at"`
	UpdatedAt           time.Time             `json:"updated_at"`
}

type CreatePrivacyActivityInput struct {
	ActivityKey         string   `json:"activity_key"`
	ServiceName         string   `json:"service_name"`
	Purpose             string   `json:"purpose"`
	DataClassifications []string `json:"data_classifications"`
	ExternalRecipients  []string `json:"external_recipients"`
	EvidenceSHA256      string   `json:"evidence_sha256"`
	OwnerSubject        string   `json:"owner_subject"`
}

func (input CreatePrivacyActivityInput) Normalize() CreatePrivacyActivityInput {
	normalized := input
	normalized.ActivityKey = strings.TrimSpace(input.ActivityKey)
	normalized.ServiceName = strings.TrimSpace(input.ServiceName)
	normalized.Purpose = strings.TrimSpace(input.Purpose)
	normalized.EvidenceSHA256 = strings.TrimSpace(input.EvidenceSHA256)
	normalized.OwnerSubject = strings.TrimSpace(input.OwnerSubject)
	normalized.DataClassifications = normalizeReferences(input.DataClassifications)
	normalized.ExternalRecipients = normalizeReferences(input.ExternalRecipients)
	return normalized
}

func (input CreatePrivacyActivityInput) Validate() error {
	if err := validateReference("activity_key", input.ActivityKey, 128); err != nil {
		return err
	}
	if err := validateReference("service_name", input.ServiceName, 128); err != nil {
		return err
	}
	if input.Purpose == "" || len(input.Purpose) > 2048 {
		return errors.New("purpose must be non-empty and at most 2048 characters")
	}
	if len(input.DataClassifications) == 0 || len(input.DataClassifications) > 16 {
		return errors.New("data_classifications must contain between 1 and 16 values")
	}
	if len(input.ExternalRecipients) > 32 {
		return errors.New("external_recipients must contain at most 32 values")
	}
	for _, values := range [][]string{input.DataClassifications, input.ExternalRecipients} {
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			if err := validateReference("privacy reference", value, 128); err != nil {
				return err
			}
			if _, exists := seen[value]; exists {
				return fmt.Errorf("privacy reference %q is duplicated", value)
			}
			seen[value] = struct{}{}
		}
	}
	if len(input.EvidenceSHA256) != len("sha256:")+64 || !strings.HasPrefix(input.EvidenceSHA256, "sha256:") {
		return errors.New("evidence_sha256 must be a canonical sha256 digest")
	}
	for _, character := range input.EvidenceSHA256[len("sha256:"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return errors.New("evidence_sha256 must be a canonical sha256 digest")
		}
	}
	return validateSubject("owner_subject", input.OwnerSubject)
}

type PrivacyDecisionInput struct {
	ExpectedVersion   int64      `json:"expected_version"`
	Decision          string     `json:"decision"`
	Reason            string     `json:"reason"`
	EvidenceSHA256    string     `json:"evidence_sha256"`
	ApprovalExpiresAt *time.Time `json:"approval_expires_at,omitempty"`
}

func (input PrivacyDecisionInput) Normalize() PrivacyDecisionInput {
	normalized := input
	normalized.Decision = strings.TrimSpace(input.Decision)
	normalized.Reason = strings.TrimSpace(input.Reason)
	normalized.EvidenceSHA256 = strings.TrimSpace(input.EvidenceSHA256)
	return normalized
}

func (input PrivacyDecisionInput) Validate() error {
	if input.ExpectedVersion <= 0 {
		return errors.New("expected_version must be positive")
	}
	if input.Decision != string(PrivacyActivityConditionallyApproved) && input.Decision != string(PrivacyActivityApproved) && input.Decision != string(PrivacyActivityRejected) {
		return errors.New("privacy decision must be conditionally_approved, approved or rejected")
	}
	if len(input.Reason) > 4096 {
		return errors.New("privacy decision reason must be at most 4096 characters")
	}
	if err := (CreatePrivacyActivityInput{EvidenceSHA256: input.EvidenceSHA256}).ValidateEvidenceSHA256(); err != nil {
		return err
	}
	if input.Decision == string(PrivacyActivityConditionallyApproved) {
		if input.ApprovalExpiresAt == nil || !input.ApprovalExpiresAt.After(time.Now().UTC()) || input.ApprovalExpiresAt.After(time.Now().UTC().Add(180*24*time.Hour)) {
			return errors.New("conditionally approved privacy decision requires an expiry within 180 days")
		}
	} else if input.ApprovalExpiresAt != nil {
		return errors.New("only conditionally approved privacy decisions may have an expiry")
	}
	return nil
}

func (input CreatePrivacyActivityInput) ValidateEvidenceSHA256() error {
	if len(input.EvidenceSHA256) != len("sha256:")+64 || !strings.HasPrefix(input.EvidenceSHA256, "sha256:") {
		return errors.New("evidence_sha256 must be a canonical sha256 digest")
	}
	for _, character := range input.EvidenceSHA256[len("sha256:"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return errors.New("evidence_sha256 must be a canonical sha256 digest")
		}
	}
	return nil
}

func normalizeReferences(values []string) []string {
	normalized := make([]string, len(values))
	for index, value := range values {
		normalized[index] = strings.TrimSpace(value)
	}
	return normalized
}

func validateReference(name, value string, limit int) error {
	if value == "" || len(value) > limit {
		return fmt.Errorf("%s must be non-empty and at most %d characters", name, limit)
	}
	for index, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-') || (index == 0 && !(character >= 'a' && character <= 'z')) {
			return fmt.Errorf("%s must be a lowercase canonical reference", name)
		}
	}
	return nil
}

func validateSubject(name, value string) error {
	if value == "" || len(value) > 512 || value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must be canonical text of at most 512 characters", name)
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return fmt.Errorf("%s must not contain whitespace or control characters", name)
		}
	}
	return nil
}

type PrivacyWorkflowInput struct {
	ExpectedVersion int64  `json:"expected_version"`
	Reason          string `json:"reason"`
	EvidenceSHA256  string `json:"evidence_sha256"`
}

func (input PrivacyWorkflowInput) Normalize() PrivacyWorkflowInput {
	input.Reason = strings.TrimSpace(input.Reason)
	input.EvidenceSHA256 = strings.TrimSpace(input.EvidenceSHA256)
	return input
}

func (input PrivacyWorkflowInput) Validate() error {
	if input.ExpectedVersion <= 0 {
		return errors.New("expected_version must be positive")
	}
	if len(input.Reason) > 4096 {
		return errors.New("privacy workflow reason must be at most 4096 characters")
	}
	return (CreatePrivacyActivityInput{EvidenceSHA256: input.EvidenceSHA256}).ValidateEvidenceSHA256()
}
