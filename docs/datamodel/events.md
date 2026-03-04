# Data Model — Event Taxonomy

**Version:** 0.1  
**Status:** Draft

This document defines the canonical event types recognized by AITC across all ingestion sources (Okta, Microsoft 365). All raw events from source systems are normalized to one of these types during ingestion.

Event types use `snake_case` and are namespaced by category.

---

## 1. Event Categories

| Category | `eventCategory` value | Description |
|---|---|---|
| Authentication | `auth` | Sign-in, sign-out, MFA, SSO events |
| Administrative Change | `admin_change` | Changes to users, groups, policies, roles |
| SaaS Action | `saas_action` | Productivity actions within SaaS apps (Teams, SharePoint, Exchange) |
| OAuth Grant | `oauth_grant` | OAuth application authorization and token events |
| Mailbox Rule | `mailbox_rule` | Exchange / Outlook inbox rule creation or modification |
| File Access | `file_access` | SharePoint / OneDrive file read, write, share, delete |
| Other | `other` | Events that do not fit another category; preserved for forensics |

---

## 2. Authentication Events (`auth`)

| `eventType` | Source(s) | Description |
|---|---|---|
| `auth.login.success` | Okta, M365 | Successful interactive sign-in |
| `auth.login.failure` | Okta, M365 | Failed interactive sign-in (bad password, locked account, etc.) |
| `auth.login.blocked` | Okta | Sign-in blocked by Okta policy (conditional access, network zone) |
| `auth.logout` | Okta | Explicit sign-out |
| `auth.session.revoked` | Okta | Session revoked (by admin, policy, or AITC action) |
| `auth.mfa.success` | Okta, M365 | MFA challenge satisfied |
| `auth.mfa.failure` | Okta, M365 | MFA challenge failed |
| `auth.mfa.push_denied` | Okta | User explicitly denied an MFA push (potential MFA fatigue indicator) |
| `auth.mfa.stepup` | Okta | MFA step-up triggered mid-session |
| `auth.password.reset` | Okta, M365 | Password reset (self-service or admin-initiated) |
| `auth.password.change` | Okta, M365 | Password changed by user |
| `auth.sso.saml` | Okta | SAML assertion issued (SSO to downstream app) |
| `auth.sso.oidc` | Okta, M365 | OIDC token issued (SSO to downstream app) |
| `auth.token.refresh` | Okta, M365 | OAuth refresh token used |
| `auth.token.revoked` | Okta, M365 | OAuth token revoked |
| `auth.device.trust_verified` | Okta | Device trust verified during sign-in |
| `auth.device.trust_failed` | Okta | Device trust check failed |
| `auth.risky_sign_in` | M365 | Azure AD Identity Protection risky sign-in alert |
| `auth.impossible_travel` | AITC (derived) | AITC-detected impossible travel signal (not a raw source event) |

---

## 3. Administrative Change Events (`admin_change`)

| `eventType` | Source(s) | Description |
|---|---|---|
| `admin_change.user.created` | Okta, M365 | New user account created |
| `admin_change.user.updated` | Okta, M365 | User profile or attributes updated |
| `admin_change.user.deactivated` | Okta | User deactivated in Okta |
| `admin_change.user.reactivated` | Okta | User reactivated in Okta |
| `admin_change.user.suspended` | Okta | User suspended |
| `admin_change.user.unsuspended` | Okta | User unsuspended |
| `admin_change.group.created` | Okta, M365 | Security group / Okta group created |
| `admin_change.group.deleted` | Okta, M365 | Group deleted |
| `admin_change.group.member_added` | Okta, M365 | User added to group |
| `admin_change.group.member_removed` | Okta, M365 | User removed from group |
| `admin_change.role.assigned` | Okta, M365 | Admin role assigned to user |
| `admin_change.role.unassigned` | Okta, M365 | Admin role removed from user |
| `admin_change.policy.created` | Okta | Okta policy created |
| `admin_change.policy.updated` | Okta | Okta policy updated (includes AITC-initiated changes) |
| `admin_change.policy.deleted` | Okta | Okta policy deleted |
| `admin_change.app.assigned` | Okta | Application assigned to user or group |
| `admin_change.app.unassigned` | Okta | Application unassigned |
| `admin_change.mfa.enrolled` | Okta | MFA factor enrolled for user |
| `admin_change.mfa.unenrolled` | Okta | MFA factor removed from user |
| `admin_change.api_token.created` | Okta | Okta API token created |
| `admin_change.api_token.revoked` | Okta | Okta API token revoked |

---

## 4. SaaS Action Events (`saas_action`)

| `eventType` | Source(s) | Description |
|---|---|---|
| `saas_action.teams.message_sent` | M365 | Teams message sent (metadata only; no content) |
| `saas_action.teams.channel_created` | M365 | Teams channel created |
| `saas_action.teams.external_access` | M365 | Teams external user added to channel or chat |
| `saas_action.exchange.email_forwarding_set` | M365 | Auto-forwarding rule set on mailbox |
| `saas_action.exchange.email_sent` | M365 | Email sent (metadata: sender, recipients, subject hash) |
| `saas_action.sharepoint.site_created` | M365 | SharePoint site created |
| `saas_action.sharepoint.external_share` | M365 | Content shared externally |

---

## 5. OAuth Grant Events (`oauth_grant`)

| `eventType` | Source(s) | Description |
|---|---|---|
| `oauth_grant.app.authorized` | Okta, M365 | User authorized an OAuth application |
| `oauth_grant.app.revoked` | Okta, M365 | OAuth application authorization revoked |
| `oauth_grant.scope.elevated` | Okta | OAuth application granted elevated/sensitive scopes |
| `oauth_grant.token.issued` | Okta | OAuth access token issued |

---

## 6. Mailbox Rule Events (`mailbox_rule`)

| `eventType` | Source(s) | Description |
|---|---|---|
| `mailbox_rule.created` | M365 | Inbox rule created (all rules logged regardless of target) |
| `mailbox_rule.updated` | M365 | Inbox rule modified |
| `mailbox_rule.deleted` | M365 | Inbox rule deleted |
| `mailbox_rule.forward_created` | M365 | Forwarding-specific rule created (high-risk; triggers RiskSignal) |

---

## 7. File Access Events (`file_access`)

| `eventType` | Source(s) | Description |
|---|---|---|
| `file_access.viewed` | M365 | File viewed in SharePoint / OneDrive |
| `file_access.downloaded` | M365 | File downloaded |
| `file_access.uploaded` | M365 | File uploaded |
| `file_access.deleted` | M365 | File deleted |
| `file_access.shared_internal` | M365 | File shared with internal users |
| `file_access.shared_external` | M365 | File shared with external users or anonymous link |
| `file_access.bulk_download` | AITC (derived) | AITC-detected bulk download pattern (not a raw source event) |

---

## 8. AITC-Derived Events

These event types are generated by AITC's Risk Engine, not ingested from external sources. They appear in the event log alongside raw events to provide a complete audit timeline.

| `eventType` | Description |
|---|---|
| `aitc.risk.signal_created` | A new RiskSignal was generated by the Risk Engine |
| `aitc.case.opened` | A Case was opened |
| `aitc.case.closed` | A Case was closed |
| `aitc.action.proposed` | A ResponseAction was proposed |
| `aitc.action.validated` | A ResponseAction passed policy validation |
| `aitc.action.rejected` | A ResponseAction was rejected by the policy validator |
| `aitc.action.executed` | A ResponseAction was executed at the target system |
| `aitc.action.reverted` | A ResponseAction was reverted by an analyst |
| `aitc.learning_mode.started` | Learning mode began for an identity |
| `aitc.learning_mode.ended` | Learning mode ended; autopilot enabled |

---

## 9. Source Mapping Reference

### 9.1 Okta System Log → AITC Event Type

| Okta `eventType` | AITC `eventType` |
|---|---|
| `user.session.start` | `auth.login.success` |
| `user.session.end` | `auth.logout` |
| `user.authentication.auth_via_mfa` | `auth.mfa.success` |
| `user.mfa.factor.deactivate` | `admin_change.mfa.unenrolled` |
| `policy.evaluate_sign_on` | *(internal; not stored as user event)* |
| `user.account.update_password` | `auth.password.change` |
| `user.lifecycle.create` | `admin_change.user.created` |
| `user.lifecycle.deactivate` | `admin_change.user.deactivated` |
| `group.user_membership.add` | `admin_change.group.member_added` |
| `application.user_membership.add` | `admin_change.app.assigned` |
| `system.api_token.create` | `admin_change.api_token.created` |

### 9.2 M365 UAL → AITC Event Type

| M365 UAL `Operation` | AITC `eventType` |
|---|---|
| `UserLoggedIn` | `auth.login.success` |
| `UserLoginFailed` | `auth.login.failure` |
| `New-InboxRule` | `mailbox_rule.created` |
| `Set-InboxRule` | `mailbox_rule.updated` |
| `FileDownloaded` | `file_access.downloaded` |
| `SharingSet` | `file_access.shared_external` (if external) or `file_access.shared_internal` |
| `Add member to role` | `admin_change.role.assigned` |
| `Add-MailboxPermission` | `admin_change.user.updated` |
