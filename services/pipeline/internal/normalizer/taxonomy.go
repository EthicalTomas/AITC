// Package normalizer maps raw Okta and M365 events to the canonical AITC
// event taxonomy defined in docs/datamodel/events.md.
package normalizer

import (
"strings"

eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
)

// OktaEventTypeToCategory maps an Okta System Log event type to an EventCategory.
func OktaEventTypeToCategory(eventType string) eventspb.EventCategory {
switch {
case strings.HasPrefix(eventType, "user.session"),
strings.HasPrefix(eventType, "user.authentication"),
strings.HasPrefix(eventType, "user.account"):
return eventspb.EventCategory_AUTHENTICATION
case strings.HasPrefix(eventType, "user.mfa"):
return eventspb.EventCategory_MFA
case strings.HasPrefix(eventType, "user.lifecycle"),
strings.HasPrefix(eventType, "group."),
strings.HasPrefix(eventType, "application."),
strings.HasPrefix(eventType, "system."):
return eventspb.EventCategory_ADMIN
case strings.HasPrefix(eventType, "policy."):
return eventspb.EventCategory_POLICY_CHANGE
default:
return eventspb.EventCategory_OTHER
}
}

// OktaEventTypeToAction maps an Okta event type to a normalized AITC action name.
func OktaEventTypeToAction(eventType string) string {
switch eventType {
case "user.session.start":
return "auth.login.success"
case "user.session.end":
return "auth.logout"
case "user.authentication.auth_via_mfa":
return "auth.mfa.success"
case "user.mfa.okta_verify.deny":
return "auth.mfa.push_denied"
case "user.mfa.factor.activate":
return "admin.mfa.factor.enrolled"
case "user.mfa.factor.deactivate":
return "admin.mfa.factor.unenrolled"
case "user.account.update_password":
return "auth.password.change"
case "user.account.reset_password":
return "auth.password.reset"
case "user.lifecycle.create":
return "admin.user.created"
case "user.lifecycle.deactivate":
return "admin.user.deactivated"
case "user.lifecycle.reactivate":
return "admin.user.reactivated"
case "user.lifecycle.suspend":
return "admin.user.suspended"
case "user.lifecycle.unsuspend":
return "admin.user.unsuspended"
case "group.user_membership.add":
return "admin.group.member_added"
case "group.user_membership.remove":
return "admin.group.member_removed"
case "application.user_membership.add":
return "admin.app.assigned"
case "application.user_membership.remove":
return "admin.app.unassigned"
case "system.api_token.create":
return "admin.api_token.created"
case "system.api_token.revoke":
return "admin.api_token.revoked"
case "policy.lifecycle.create":
return "admin.policy.created"
case "policy.lifecycle.update":
return "admin.policy.updated"
case "policy.lifecycle.delete":
return "admin.policy.deleted"
default:
return eventType
}
}

// OktaOutcomeToNormalized maps an Okta outcome result to "success", "failure", or "unknown".
func OktaOutcomeToNormalized(result string) string {
switch result {
case "SUCCESS", "ALLOW":
return "success"
case "FAILURE", "DENY":
return "failure"
default:
return "unknown"
}
}

// M365OperationToCategory maps an M365 UAL Operation to an EventCategory.
func M365OperationToCategory(operation string) eventspb.EventCategory {
switch operation {
case "MailboxLogin", "UserLoggedIn", "UserLoginFailed":
return eventspb.EventCategory_AUTHENTICATION
case "New-InboxRule", "Set-InboxRule", "Remove-InboxRule", "UpdateInboxRules":
return eventspb.EventCategory_EMAIL
case "FileDownloaded", "FileUploaded", "FileAccessed",
"FilePreviewed", "FileDeleted", "FileSyncDownloadedFull",
"SharingSet", "SecureLinkCreated", "AnonymousLinkCreated",
"SharingInvitationCreated":
return eventspb.EventCategory_FILE
case "Add member to role.", "Remove member from role.",
"Add user.", "Delete user.", "Update user.",
"Add-MailboxPermission", "Set-Mailbox":
return eventspb.EventCategory_ADMIN
case "Add app role assignment to service principal.",
"Add delegated permission grant.",
"Consent to application.":
return eventspb.EventCategory_OAUTH
case "Set-TransportRule", "New-TransportRule", "Set-OrganizationConfig":
return eventspb.EventCategory_POLICY_CHANGE
default:
return eventspb.EventCategory_OTHER
}
}

// M365OperationToAction maps an M365 UAL Operation to a normalized AITC action name.
func M365OperationToAction(operation string) string {
switch operation {
case "MailboxLogin", "UserLoggedIn":
return "auth.login.success"
case "UserLoginFailed":
return "auth.login.failure"
case "New-InboxRule":
return "mailbox_rule.created"
case "Set-InboxRule", "UpdateInboxRules":
return "mailbox_rule.updated"
case "Remove-InboxRule":
return "mailbox_rule.deleted"
case "FileDownloaded", "FileSyncDownloadedFull":
return "file.downloaded"
case "FileUploaded":
return "file.uploaded"
case "FileAccessed", "FilePreviewed":
return "file.accessed"
case "FileDeleted":
return "file.deleted"
case "SharingSet", "SharingInvitationCreated":
return "file.shared"
case "AnonymousLinkCreated":
return "file.anonymous_link_created"
case "Add member to role.":
return "admin.role.assigned"
case "Remove member from role.":
return "admin.role.unassigned"
case "Add user.":
return "admin.user.created"
case "Delete user.":
return "admin.user.deleted"
case "Add-MailboxPermission":
return "admin.mailbox_permission.added"
case "Add app role assignment to service principal.":
return "oauth.app_role.assigned"
case "Add delegated permission grant.":
return "oauth.delegated_permission.granted"
case "Consent to application.":
return "oauth.app.consent"
default:
return operation
}
}

// M365ResultToNormalized maps an M365 result status to "success", "failure", or "unknown".
func M365ResultToNormalized(result string) string {
switch result {
case "Succeeded", "True":
return "success"
case "Failed", "False":
return "failure"
default:
return "unknown"
}
}

// IsPrivilegedOktaActor returns true for Okta actor types indicating elevated privileges.
func IsPrivilegedOktaActor(actorType string) bool {
return actorType == "SystemPrincipal" || actorType == "SystemUser"
}

// IsPrivilegedM365User returns true for M365 user type codes indicating admin access.
// 0=Regular, 2=Admin, 3=DcAdmin, 4=System, 5=Application.
func IsPrivilegedM365User(userTypeCode string) bool {
switch userTypeCode {
case "2", "3", "4", "5":
return true
}
return false
}
