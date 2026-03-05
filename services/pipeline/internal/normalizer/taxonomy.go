// Package normalizer maps raw source events to AITC canonical event types.
// Taxonomy is defined in docs/datamodel/events.md.
package normalizer

import eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"

// categoryForOktaEventType maps an Okta System Log eventType string to an
// AITC EventCategory and a normalized action name.
func categoryForOktaEventType(eventType string) (eventspb.EventCategory, string) {
	switch eventType {
	// ── Authentication ────────────────────────────────────────────────────────
	case "user.session.start":
		return eventspb.EventCategory_AUTHENTICATION, "auth.login.success"
	case "user.session.end":
		return eventspb.EventCategory_SESSION, "auth.logout"
	case "user.authentication.auth_via_mfa",
		"user.authentication.auth_via_mfa_factor":
		return eventspb.EventCategory_MFA, "auth.mfa.success"
	case "user.mfa.okta_verify.deny",
		"user.mfa.factor.challenge.deny":
		return eventspb.EventCategory_MFA, "auth.mfa.push_denied"
	case "user.authentication.sso",
		"user.authentication.auth_via_IDP":
		return eventspb.EventCategory_AUTHENTICATION, "auth.sso.saml"
	case "user.account.update_password":
		return eventspb.EventCategory_AUTHENTICATION, "auth.password.change"
	case "user.account.reset_password":
		return eventspb.EventCategory_AUTHENTICATION, "auth.password.reset"
	case "user.session.impersonation.initiate":
		return eventspb.EventCategory_SESSION, "auth.session.impersonation"

	// ── MFA ───────────────────────────────────────────────────────────────────
	case "user.mfa.factor.activate":
		return eventspb.EventCategory_MFA, "admin_change.mfa.enrolled"
	case "user.mfa.factor.deactivate":
		return eventspb.EventCategory_MFA, "admin_change.mfa.unenrolled"
	case "user.mfa.factor.update":
		return eventspb.EventCategory_MFA, "admin_change.mfa.enrolled"

	// ── Admin change ──────────────────────────────────────────────────────────
	case "user.lifecycle.create":
		return eventspb.EventCategory_ADMIN, "admin_change.user.created"
	case "user.lifecycle.deactivate":
		return eventspb.EventCategory_ADMIN, "admin_change.user.deactivated"
	case "user.lifecycle.reactivate":
		return eventspb.EventCategory_ADMIN, "admin_change.user.reactivated"
	case "user.lifecycle.suspend":
		return eventspb.EventCategory_ADMIN, "admin_change.user.suspended"
	case "user.lifecycle.unsuspend":
		return eventspb.EventCategory_ADMIN, "admin_change.user.unsuspended"
	case "user.account.update_profile":
		return eventspb.EventCategory_ADMIN, "admin_change.user.updated"
	case "group.user_membership.add":
		return eventspb.EventCategory_ADMIN, "admin_change.group.member_added"
	case "group.user_membership.remove":
		return eventspb.EventCategory_ADMIN, "admin_change.group.member_removed"
	case "group.lifecycle.create":
		return eventspb.EventCategory_ADMIN, "admin_change.group.created"
	case "group.lifecycle.delete":
		return eventspb.EventCategory_ADMIN, "admin_change.group.deleted"
	case "application.user_membership.add":
		return eventspb.EventCategory_ADMIN, "admin_change.app.assigned"
	case "application.user_membership.remove":
		return eventspb.EventCategory_ADMIN, "admin_change.app.unassigned"
	case "system.api_token.create":
		return eventspb.EventCategory_ADMIN, "admin_change.api_token.created"
	case "system.api_token.revoke":
		return eventspb.EventCategory_ADMIN, "admin_change.api_token.revoked"

	// ── Policy change ─────────────────────────────────────────────────────────
	case "policy.lifecycle.create":
		return eventspb.EventCategory_POLICY_CHANGE, "admin_change.policy.created"
	case "policy.lifecycle.update",
		"policy.rule.update":
		return eventspb.EventCategory_POLICY_CHANGE, "admin_change.policy.updated"
	case "policy.lifecycle.delete":
		return eventspb.EventCategory_POLICY_CHANGE, "admin_change.policy.deleted"

	// ── OAuth ─────────────────────────────────────────────────────────────────
	case "app.oauth2.as.authorize.success",
		"app.oauth2.authorize":
		return eventspb.EventCategory_OAUTH, "oauth_grant.app.authorized"
	case "app.oauth2.token.grant.access_token":
		return eventspb.EventCategory_OAUTH, "oauth_grant.token.issued"

	default:
		return eventspb.EventCategory_OTHER, eventType
	}
}

// categoryForM365Operation maps an M365 UAL Operation string to an AITC
// EventCategory and a normalized action name.
func categoryForM365Operation(operation string) (eventspb.EventCategory, string) {
	switch operation {
	// ── Authentication ────────────────────────────────────────────────────────
	case "UserLoggedIn":
		return eventspb.EventCategory_AUTHENTICATION, "auth.login.success"
	case "UserLoginFailed":
		return eventspb.EventCategory_AUTHENTICATION, "auth.login.failure"
	case "UserLoggedOut":
		return eventspb.EventCategory_SESSION, "auth.logout"

	// ── Mailbox rule ──────────────────────────────────────────────────────────
	case "New-InboxRule":
		return eventspb.EventCategory_EMAIL, "mailbox_rule.created"
	case "Set-InboxRule":
		return eventspb.EventCategory_EMAIL, "mailbox_rule.updated"
	case "Remove-InboxRule":
		return eventspb.EventCategory_EMAIL, "mailbox_rule.deleted"
	case "Set-Mailbox":
		return eventspb.EventCategory_EMAIL, "mailbox_rule.updated"

	// ── File access ───────────────────────────────────────────────────────────
	case "FileDownloaded":
		return eventspb.EventCategory_FILE, "file_access.downloaded"
	case "FileViewed", "FileAccessed":
		return eventspb.EventCategory_FILE, "file_access.viewed"
	case "FileUploaded":
		return eventspb.EventCategory_FILE, "file_access.uploaded"
	case "FileDeleted":
		return eventspb.EventCategory_FILE, "file_access.deleted"
	case "SharingSet", "AnonymousLinkCreated":
		return eventspb.EventCategory_FILE, "file_access.shared_external"
	case "AddedToSecureLink":
		return eventspb.EventCategory_FILE, "file_access.shared_internal"

	// ── Admin change ──────────────────────────────────────────────────────────
	case "Add member to role.", "Add member to role":
		return eventspb.EventCategory_ADMIN, "admin_change.role.assigned"
	case "Remove member from role.":
		return eventspb.EventCategory_ADMIN, "admin_change.role.unassigned"
	case "Add-MailboxPermission":
		return eventspb.EventCategory_ADMIN, "admin_change.user.updated"
	case "Add user.":
		return eventspb.EventCategory_ADMIN, "admin_change.user.created"
	case "Delete user.":
		return eventspb.EventCategory_ADMIN, "admin_change.user.deactivated"
	case "Update user.":
		return eventspb.EventCategory_ADMIN, "admin_change.user.updated"

	// ── OAuth ─────────────────────────────────────────────────────────────────
	case "Consent to application.":
		return eventspb.EventCategory_OAUTH, "oauth_grant.app.authorized"

	default:
		return eventspb.EventCategory_OTHER, operation
	}
}

