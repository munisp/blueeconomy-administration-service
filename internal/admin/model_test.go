package admin

import "testing"

func TestSubmitInputRejectsUndeclaredRole(t *testing.T) {
	input := SubmitInput{
		OrganizationID: "approved-org",
		Email:          "operator@example.invalid",
		FirstName:      "Operator",
		LastName:       "One",
		RequestedRoles: []string{"unapproved.role"},
	}
	if err := input.Validate("approved-org", map[string]struct{}{"approved.role": {}}); err == nil {
		t.Fatal("expected an undeclared role to be rejected")
	}
}

func TestCanApproveRejectsSelfApproval(t *testing.T) {
	if err := CanApprove("subject-1", "subject-1"); err == nil {
		t.Fatal("expected self-approval to be rejected")
	}
}

func TestSubmitInputAcceptsApprovedRole(t *testing.T) {
	input := SubmitInput{
		OrganizationID: "approved-org",
		Email:          "operator@example.invalid",
		FirstName:      "Operator",
		LastName:       "One",
		RequestedRoles: []string{"approved.role"},
	}
	if err := input.Validate("approved-org", map[string]struct{}{"approved.role": {}}); err != nil {
		t.Fatalf("expected approved request to pass validation: %v", err)
	}
}

func TestSubmitInputAcceptsConfiguredOrganization(t *testing.T) {
	organizationID := "d6b44d5e-087e-47f4-8330-e36bd944f4c2"
	input := SubmitInput{
		OrganizationID: organizationID,
		Email:          "stakeholder.local@blueeconomy.test",
		FirstName:      "Local",
		LastName:       "Stakeholder",
		RequestedRoles: []string{"safety.telemetry.review"},
	}
	if err := input.Validate(organizationID, map[string]struct{}{"safety.telemetry.review": {}}); err != nil {
		t.Fatalf("expected configured organization to be accepted: %v", err)
	}
}
