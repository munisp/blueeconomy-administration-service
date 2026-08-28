package admin

import (
	"encoding/json"
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
	StatusPendingVerification   RequestStatus = "pending_verification"
	StatusIdentityReview        RequestStatus = "identity_review"
	StatusIdentityVerified      RequestStatus = "identity_verified"
	StatusIdentityRejected      RequestStatus = "identity_rejected"
)

type OnboardingRequest struct {
	ID                 string        `json:"id"`
	OrganizationID     string        `json:"organization_id"`
	Email              string        `json:"email"`
	FirstName          string        `json:"first_name"`
	LastName           string        `json:"last_name"`
	RequestedRoles     []string      `json:"requested_roles"`
	RequesterSubject   string        `json:"requester_subject"`
	Status             RequestStatus `json:"status"`
	Persona            string        `json:"persona,omitempty"`
	ContactChannel     string        `json:"contact_channel,omitempty"`
	ContactReference   string        `json:"contact_reference,omitempty"`
	NotificationStatus string        `json:"notification_status,omitempty"`
	CreatedAt          time.Time     `json:"created_at"`
	UpdatedAt          time.Time     `json:"updated_at"`
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

// ErrMakerCheckerViolation marks any maker/checker separation-of-duties
// rejection so HTTP handlers can map it to 403 without string matching.
var ErrMakerCheckerViolation = errors.New("maker/checker violation")

func CanApprove(requesterSubject, approverSubject string) error {
	if strings.TrimSpace(requesterSubject) == "" || strings.TrimSpace(approverSubject) == "" {
		return errors.New("requester and approver subjects are required")
	}
	if requesterSubject == approverSubject {
		return fmt.Errorf("%w: requester cannot approve their own onboarding request", ErrMakerCheckerViolation)
	}
	return nil
}

// CanDecide enforces the decision gate fail-closed. Officer-submitted requests
// are decided from submitted; self-service enrollment requests (persona set)
// can only be decided after an officer has completed identity proofing, so a
// public enrollment can never skip KYC and reach provisioning.
func (request OnboardingRequest) CanDecide() error {
	if request.Persona == "" {
		if request.Status != StatusSubmitted {
			return fmt.Errorf("request is in %q state and cannot be decided", request.Status)
		}
		return nil
	}
	if request.Status != StatusIdentityVerified {
		return fmt.Errorf("self-service enrollment request is in %q state and must be %q before a decision", request.Status, StatusIdentityVerified)
	}
	return nil
}

// CanStartIdentityReview gates the identity-proofing start transition: only a
// self-service enrollment request waiting for verification may enter review.
func (request OnboardingRequest) CanStartIdentityReview() error {
	if request.Persona == "" {
		return errors.New("identity review applies only to self-service enrollment requests")
	}
	if request.Status != StatusPendingVerification {
		return fmt.Errorf("enrollment request is in %q state and cannot enter identity review", request.Status)
	}
	return nil
}

// CanRecordIdentityOutcome gates the identity-proofing outcome transition:
// only a request under active review may be verified or rejected.
func (request OnboardingRequest) CanRecordIdentityOutcome() error {
	if request.Status != StatusIdentityReview {
		return fmt.Errorf("enrollment request is in %q state and has no open identity review", request.Status)
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

// SelfServiceRequesterSubject is the immutable non-human requester recorded
// for public self-service enrollment submissions. It can never equal an
// officer subject, so a self-service request can never be self-approved.
const SelfServiceRequesterSubject = "enrollment:self-service"

// Approved stakeholder personas for self-service and agent-assisted
// enrollment. Anything outside this set is rejected before storage.
var approvedPersonas = map[string]struct{}{
	"trucker":          {},
	"ferry-passenger":  {},
	"operator":         {},
	"fisher":           {},
	"seafarer-trainee": {},
	"beneficiary":      {},
	"exporter":         {},
	"processor":        {},
	"fleet-operator":   {},
}

// Approved contact channels for the activation notice.
var approvedContactChannels = map[string]struct{}{
	"sms":   {},
	"ussd":  {},
	"email": {},
	"app":   {},
}

// Approved identity document types for the KYC identity-proofing stage.
var approvedDocumentTypes = map[string]struct{}{
	"passport":                 {},
	"national-id":              {},
	"drivers-license":          {},
	"seafarers-discharge-book": {},
	"voter-card":               {},
	"birth-certificate":        {},
}

type EnrollmentSubmitInput struct {
	Persona          string `json:"persona"`
	ContactChannel   string `json:"contact_channel"`
	ContactReference string `json:"contact_reference"`
	FirstName        string `json:"first_name"`
	LastName         string `json:"last_name"`
	Email            string `json:"email"`
}

func (input EnrollmentSubmitInput) Normalize() EnrollmentSubmitInput {
	normalized := input
	normalized.Persona = strings.TrimSpace(input.Persona)
	normalized.ContactChannel = strings.TrimSpace(input.ContactChannel)
	normalized.ContactReference = strings.TrimSpace(input.ContactReference)
	normalized.FirstName = strings.TrimSpace(input.FirstName)
	normalized.LastName = strings.TrimSpace(input.LastName)
	normalized.Email = strings.TrimSpace(input.Email)
	return normalized
}

// Validate enforces the self-service enrollment contract fail-closed: an
// approved persona, an approved contact channel with a channel-conformant
// reference, canonical names, and an e-mail only when the channel or the
// caller supplies a valid one.
func (input EnrollmentSubmitInput) Validate() error {
	if _, approved := approvedPersonas[input.Persona]; !approved {
		return fmt.Errorf("persona %q is not in the approved persona catalogue", input.Persona)
	}
	if _, approved := approvedContactChannels[input.ContactChannel]; !approved {
		return fmt.Errorf("contact_channel %q is not in the approved channel catalogue", input.ContactChannel)
	}
	if err := validateContactReference(input.ContactChannel, input.ContactReference); err != nil {
		return err
	}
	for _, field := range []struct{ name, value string }{{"first_name", input.FirstName}, {"last_name", input.LastName}} {
		if value := strings.TrimSpace(field.value); value == "" || len(value) > 255 {
			return fmt.Errorf("%s must be non-empty and at most 255 characters", field.name)
		}
	}
	if input.ContactChannel == "email" {
		if input.Email != input.ContactReference {
			return errors.New("email must match the contact_reference for the email channel")
		}
		return nil
	}
	if input.Email != "" {
		address, err := mail.ParseAddress(input.Email)
		if err != nil || address.Address != input.Email || len(input.Email) > 320 {
			return errors.New("email must be an approved canonical e-mail address")
		}
	}
	return nil
}

func validateContactReference(channel, value string) error {
	if value == "" || len(value) > 320 {
		return errors.New("contact_reference must be non-empty and at most 320 characters")
	}
	switch channel {
	case "sms", "ussd":
		digits := strings.TrimPrefix(value, "+")
		if len(digits) < 5 || len(digits) > 15 {
			return errors.New("contact_reference must be an E.164-style number of 5 to 15 digits")
		}
		for _, character := range digits {
			if character < '0' || character > '9' {
				return errors.New("contact_reference must be an E.164-style number of 5 to 15 digits")
			}
		}
		return nil
	case "email":
		address, err := mail.ParseAddress(value)
		if err != nil || address.Address != value {
			return errors.New("contact_reference must be an approved canonical e-mail address")
		}
		return nil
	default:
		return validateReference("contact_reference", value, 128)
	}
}

// IdentityVerificationInput records an officer's identity-proofing outcome.
// Only the sha256 digest of the document reference is accepted; raw document
// numbers are rejected by validation and never stored.
type IdentityVerificationInput struct {
	Outcome                 string `json:"outcome"`
	DocumentType            string `json:"document_type"`
	DocumentReferenceSHA256 string `json:"document_reference_sha256"`
	Reason                  string `json:"reason"`
}

func (input IdentityVerificationInput) Normalize() IdentityVerificationInput {
	normalized := input
	normalized.Outcome = strings.TrimSpace(input.Outcome)
	normalized.DocumentType = strings.TrimSpace(input.DocumentType)
	normalized.DocumentReferenceSHA256 = strings.TrimSpace(input.DocumentReferenceSHA256)
	normalized.Reason = strings.TrimSpace(input.Reason)
	return normalized
}

func (input IdentityVerificationInput) Validate() error {
	if input.Outcome != string(StatusIdentityVerified) && input.Outcome != string(StatusIdentityRejected) {
		return errors.New("outcome must be identity_verified or identity_rejected")
	}
	if _, approved := approvedDocumentTypes[input.DocumentType]; !approved {
		return fmt.Errorf("document_type %q is not in the approved document catalogue", input.DocumentType)
	}
	if err := validateSHA256Digest("document_reference_sha256", input.DocumentReferenceSHA256); err != nil {
		return err
	}
	if len(input.Reason) > 1024 {
		return errors.New("identity verification reason must be at most 1024 characters")
	}
	return nil
}

// MaxEnrollmentBatchRows bounds one agent-assisted enrollment batch.
const MaxEnrollmentBatchRows = 500

type EnrollmentBatchInput struct {
	Rows []EnrollmentSubmitInput `json:"rows"`
}

func (input EnrollmentBatchInput) Normalize() EnrollmentBatchInput {
	normalized := EnrollmentBatchInput{Rows: make([]EnrollmentSubmitInput, len(input.Rows))}
	for index, row := range input.Rows {
		normalized.Rows[index] = row.Normalize()
	}
	return normalized
}

func (input EnrollmentBatchInput) Validate() error {
	if len(input.Rows) == 0 || len(input.Rows) > MaxEnrollmentBatchRows {
		return fmt.Errorf("a batch must contain between 1 and %d rows", MaxEnrollmentBatchRows)
	}
	return nil
}

// ValidateEnrollmentRows validates every row independently so a single bad
// row never rejects the batch and never fails silently: each row carries an
// explicit accepted/rejected status into storage.
func ValidateEnrollmentRows(rows []EnrollmentSubmitInput) []error {
	results := make([]error, len(rows))
	for index, row := range rows {
		results[index] = row.Validate()
	}
	return results
}

// CanConfirmBatch enforces dual control: the confirming officer must differ
// from the proposing officer. The same separation is database-enforced by the
// enrollment_batches confirmer/proposer inequality constraint.
func CanConfirmBatch(proposerSubject, confirmerSubject string) error {
	if strings.TrimSpace(proposerSubject) == "" || strings.TrimSpace(confirmerSubject) == "" {
		return errors.New("proposer and confirmer subjects are required")
	}
	if proposerSubject == confirmerSubject {
		return fmt.Errorf("%w: proposer cannot confirm their own enrollment batch", ErrMakerCheckerViolation)
	}
	return nil
}

type EnrollmentBatchStatus string

const (
	EnrollmentBatchProposed  EnrollmentBatchStatus = "proposed"
	EnrollmentBatchConfirmed EnrollmentBatchStatus = "confirmed"
)

type EnrollmentBatch struct {
	ID               string                `json:"id"`
	ProposerSubject  string                `json:"proposer_subject"`
	ConfirmerSubject string                `json:"confirmer_subject,omitempty"`
	Status           EnrollmentBatchStatus `json:"status"`
	RowCount         int                   `json:"row_count"`
	AcceptedCount    int                   `json:"accepted_count"`
	EnrolledCount    int                   `json:"enrolled_count"`
	FailedCount      int                   `json:"failed_count"`
	CreatedAt        time.Time             `json:"created_at"`
	ConfirmedAt      *time.Time            `json:"confirmed_at,omitempty"`
}

// Enrollment batch row statuses: every row ends in an explicit state, so a
// per-row failure can never fail the batch silently.
const (
	BatchRowAccepted = "accepted"
	BatchRowRejected = "rejected"
	BatchRowEnrolled = "enrolled"
	BatchRowFailed   = "failed"
)

type EnrollmentBatchRow struct {
	RowIndex  int     `json:"row_index"`
	Status    string  `json:"status"`
	Error     string  `json:"error,omitempty"`
	RequestID *string `json:"request_id,omitempty"`
}

// Outbox contract for the activation notification. The notifier (USSD/SMS
// gateway) is a separate platform component; this service owns only the
// event envelope and the delivery status tracking.
const (
	OutboxTopicPlatformOnboarding    = "platform.onboarding.v1"
	OutboxEventActivation            = "onboarding.activated.v1"
	OutboxClassificationConfidential = "CONFIDENTIAL"
)

const (
	NotificationPending = "pending"
	NotificationSent    = "sent"
	NotificationFailed  = "failed"
)

const (
	OutboxPending = "pending"
	OutboxClaimed = "claimed"
	OutboxSent    = "sent"
	OutboxFailed  = "failed"
)

// ActivationNoticePayload carries exactly what the notifier needs to deliver
// credential instructions: the contact-channel reference and nothing else
// that identifies the person.
type ActivationNoticePayload struct {
	RequestID        string    `json:"request_id"`
	Persona          string    `json:"persona,omitempty"`
	ContactChannel   string    `json:"contact_channel"`
	ContactReference string    `json:"contact_reference"`
	ActivatedAt      time.Time `json:"activated_at"`
}

type ActivationNotice struct {
	Topic               string                  `json:"topic"`
	EventType           string                  `json:"event_type"`
	Classification      string                  `json:"classification"`
	ProvenancePrincipal string                  `json:"provenance_principal"`
	Payload             ActivationNoticePayload `json:"payload"`
}

// NewActivationNotice maps an activated request onto the platform envelope.
// Officer-path requests without an explicit contact channel fall back to
// their approved e-mail address; self-service requests use the recorded
// contact channel. The mapping is total: every activation yields exactly one
// deliverable notice.
func NewActivationNotice(request OnboardingRequest, principal string, activatedAt time.Time) ActivationNotice {
	channel := request.ContactChannel
	reference := request.ContactReference
	if reference == "" {
		channel = "email"
		reference = request.Email
	}
	return ActivationNotice{
		Topic:               OutboxTopicPlatformOnboarding,
		EventType:           OutboxEventActivation,
		Classification:      OutboxClassificationConfidential,
		ProvenancePrincipal: principal,
		Payload: ActivationNoticePayload{
			RequestID:        request.ID,
			Persona:          request.Persona,
			ContactChannel:   channel,
			ContactReference: reference,
			ActivatedAt:      activatedAt,
		},
	}
}

type OutboxEvent struct {
	ID                  string          `json:"id"`
	RequestID           string          `json:"request_id"`
	Topic               string          `json:"topic"`
	EventType           string          `json:"event_type"`
	Classification      string          `json:"classification"`
	ProvenancePrincipal string          `json:"provenance_principal"`
	Payload             json.RawMessage `json:"payload"`
	Status              string          `json:"status"`
	Attempt             int             `json:"attempt"`
	CreatedAt           time.Time       `json:"created_at"`
}

func validateSHA256Digest(name, value string) error {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return fmt.Errorf("%s must be a canonical sha256 digest", name)
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return fmt.Errorf("%s must be a canonical sha256 digest", name)
		}
	}
	return nil
}
