# BlueEconomy administration-service PBAC policy.
#
# Evaluated by internal/pbac (embedded OPA) on every privileged
# administration route. Deny-by-default: any input not matching an explicit
# allow rule is denied. The authorization input is
# {roles, clearance, tenant_id, resource, action, classification}.
package blueeconomy.admin

import rego.v1

default allow := false

# Realm-role capability sets (mirror of the service route policy, expressed
# as declarative, independently auditable policy).
approver_roles := {"platform-admin", "nimasa-officer"}

operator_roles := {"platform-admin", "nimasa-officer", "nwa-officer", "niwa-officer"}

read_only_roles := {"cbn-observer", "fmmbe-oversight", "independent-auditor", "icrc-observer"}

recognized_roles := approver_roles | operator_roles | read_only_roles

# National-security clearance ladder (record-level labels).
clearance_levels := {
	"UNCLASSIFIED": 0,
	"RESTRICTED": 1,
	"CONFIDENTIAL": 2,
	"SECRET": 3,
}

# Platform data-classification ladder (envelope contract values).
classification_levels := {
	"PUBLIC": 0,
	"INTERNAL": 0,
	"CONFIDENTIAL": 1,
	"RESTRICTED": 2,
	"FIDUCIARY_SEGREGATED": 3,
}

# Tenant-scoped onboarding administration: an approver may decide, provision
# or activate an onboarding request, or list the approver queue collection,
# only within their own tenant/agency.
allow if {
	input.resource.kind == "onboarding_request"
	input.action in {"decide", "provision", "activate", "list"}
	some role in input.roles
	role in approver_roles
	not holds_read_only_role
	tenant_scoped
}

# Operator-grade onboarding intake actions stay inside the caller's tenant.
allow if {
	input.resource.kind == "onboarding_request"
	input.action in {"submit", "read"}
	some role in input.roles
	role in operator_roles
	not holds_read_only_role
	tenant_scoped
}

# Classifier-gated document access: a reader may read a document only when
# their clearance meets or exceeds the document classification, within their
# own tenant. Unknown labels resolve to undefined lookups and deny.
allow if {
	input.resource.kind == "document"
	input.action == "read"
	some role in input.roles
	role in recognized_roles
	tenant_scoped
	clearance_sufficient
}

tenant_scoped if {
	input.tenant_id != ""
	input.resource.tenant_id != ""
	input.tenant_id == input.resource.tenant_id
}

holds_read_only_role if {
	some role in input.roles
	role in read_only_roles
}

clearance_sufficient if {
	level := clearance_levels[input.clearance]
	floor := classification_levels[input.classification]
	level >= floor
}
