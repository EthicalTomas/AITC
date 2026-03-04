# Data Model — Entities

**Version:** 0.1  
**Status:** Draft

All entities use UTC timestamps in ISO 8601 format (`YYYY-MM-DDTHH:mm:ssZ`). Field names use `camelCase`. The canonical JSON schema is defined in [`schemas/v1.entities.json`](./schemas/v1.entities.json).

---

## 1. Identity

The canonical cross-source identity record. Every other entity references an Identity.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string (uuid)` | ✅ | AITC-generated canonical identity ID |
| `email` | `string` | ✅ | Normalized (lowercased) primary email |
| `displayName` | `string` | ✅ | Human-readable name |
| `accountType` | `enum` | ✅ | `human`, `service`, `shared` |
| `status` | `enum` | ✅ | `active`, `suspended`, `deprovisioned` |
| `externalIds` | `object` | ✅ | Map of source → source ID (e.g., `{"okta": "00u...", "aad": "oid..."}`) |
| `department` | `string` | — | Organizational department from HR feed or directory |
| `jobTitle` | `string` | — | Job title |
| `manager` | `string (uuid)` | — | Identity ID of manager |
| `riskTier` | `enum` | — | `low`, `medium`, `high`, `critical`; derived from CAS history |
| `currentCas` | `number (0–100)` | — | Latest Continuous Authentication Score |
| `casUpdatedAt` | `timestamp` | — | When CAS was last computed |
| `learningModeUntil` | `timestamp` | — | Learning mode expiry; autopilot enabled after this |
| `tags` | `string[]` | — | Free-form tags (e.g., `executive`, `privileged`) |
| `createdAt` | `timestamp` | ✅ | When AITC first saw this identity |
| `updatedAt` | `timestamp` | ✅ | Last update to identity record |

---

## 2. Session

A single authenticated session for an identity. Sessions are opened on login events and closed on logout or timeout.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string (uuid)` | ✅ | AITC session ID |
| `identityId` | `string (uuid)` | ✅ | FK → Identity.id |
| `sourceSessionId` | `string` | ✅ | Session ID from source system (e.g., Okta session ID) |
| `source` | `enum` | ✅ | `okta`, `m365` |
| `startedAt` | `timestamp` | ✅ | Session start time (from auth event) |
| `endedAt` | `timestamp` | — | Session end time; null if active |
| `status` | `enum` | ✅ | `active`, `revoked`, `expired`, `closed` |
| `ipAddress` | `string` | ✅ | IP address at session start |
| `geoCountry` | `string` | — | ISO 3166-1 alpha-2 country code |
| `geoCity` | `string` | — | City (best-effort) |
| `userAgent` | `string` | — | User-agent string |
| `deviceId` | `string` | — | Device fingerprint or managed device ID |
| `authProtocol` | `enum` | — | `saml`, `oidc`, `oauth2`, `legacy` |
| `mfaSatisfied` | `boolean` | — | Whether MFA was satisfied during auth |
| `riskAtStart` | `number (0–100)` | — | CAS score at session start |
| `createdAt` | `timestamp` | ✅ | |
| `updatedAt` | `timestamp` | ✅ | |

---

## 3. Event

A normalized, immutable record of something that happened. All source events are mapped to this schema.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string (uuid)` | ✅ | AITC event ID |
| `sourceEventId` | `string` | ✅ | Original event ID from source system |
| `source` | `enum` | ✅ | `okta`, `m365` |
| `eventType` | `string` | ✅ | Canonical event type (see [events.md](./events.md)) |
| `eventCategory` | `enum` | ✅ | `auth`, `admin_change`, `saas_action`, `oauth_grant`, `mailbox_rule`, `file_access`, `other` |
| `identityId` | `string (uuid)` | ✅ | FK → Identity.id (resolved actor) |
| `sessionId` | `string (uuid)` | — | FK → Session.id if applicable |
| `targetIdentityId` | `string (uuid)` | — | FK → Identity.id if the event targets another identity |
| `targetResourceType` | `string` | — | Type of resource acted upon (e.g., `mailbox`, `file`, `group`, `policy`) |
| `targetResourceId` | `string` | — | ID of the resource acted upon |
| `outcome` | `enum` | ✅ | `success`, `failure`, `unknown` |
| `severity` | `enum` | — | `info`, `low`, `medium`, `high`, `critical`; set by normalization rules |
| `ipAddress` | `string` | — | Source IP of the actor |
| `geoCountry` | `string` | — | ISO 3166-1 alpha-2 |
| `userAgent` | `string` | — | |
| `raw` | `object` | ✅ | Original source event payload (preserved for auditability) |
| `occurredAt` | `timestamp` | ✅ | Time the event occurred at source |
| `ingestedAt` | `timestamp` | ✅ | Time AITC received and stored the event |
| `normalizedAt` | `timestamp` | ✅ | Time normalization completed |

---

## 4. RiskSignal

A scored anomaly detection output from the Risk Engine, associated with an identity and (optionally) a session or event.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string (uuid)` | ✅ | |
| `identityId` | `string (uuid)` | ✅ | FK → Identity.id |
| `sessionId` | `string (uuid)` | — | FK → Session.id if session-scoped |
| `triggerEventId` | `string (uuid)` | — | FK → Event.id that triggered the signal |
| `signalType` | `string` | ✅ | Detection rule/model ID (e.g., `impossible_travel`, `new_country_login`, `mfa_fatigue`) |
| `casScore` | `number (0–100)` | ✅ | CAS score at time of signal |
| `casDelta` | `number` | ✅ | Change in CAS from previous score (positive = riskier) |
| `confidence` | `number (0–1)` | ✅ | Model confidence (0 = no confidence, 1 = certain) |
| `severity` | `enum` | ✅ | `low`, `medium`, `high`, `critical` |
| `explanation` | `string` | — | Human-readable explanation of the anomaly |
| `featureSnapshot` | `object` | — | Feature values at time of scoring (for auditability/debugging) |
| `caseId` | `string (uuid)` | — | FK → Case.id once grouped into a case |
| `status` | `enum` | ✅ | `open`, `grouped`, `closed`, `false_positive` |
| `createdAt` | `timestamp` | ✅ | |
| `updatedAt` | `timestamp` | ✅ | |

---

## 5. Case

An investigation record that groups related RiskSignals and tracks the response lifecycle.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string (uuid)` | ✅ | |
| `identityId` | `string (uuid)` | ✅ | FK → Identity.id (primary subject) |
| `title` | `string` | ✅ | Human-readable case title (generated or set by analyst) |
| `summary` | `string` | — | LLM-generated narrative summary of the case |
| `status` | `enum` | ✅ | `open`, `in_progress`, `resolved`, `false_positive`, `escalated` |
| `severity` | `enum` | ✅ | `low`, `medium`, `high`, `critical`; derived from highest RiskSignal |
| `riskSignalIds` | `string[]` | ✅ | List of FK → RiskSignal.id |
| `responseActionIds` | `string[]` | — | List of FK → ResponseAction.id |
| `assignedTo` | `string` | — | Analyst user ID or `autopilot` |
| `routingMode` | `enum` | ✅ | `human_review`, `autopilot` |
| `learningModeActive` | `boolean` | ✅ | Whether learning mode was active when case opened |
| `recommendation` | `string` | — | LLM-generated recommended action text |
| `recommendedActions` | `string[]` | — | Allowlisted action types recommended (e.g., `session_revoke`) |
| `openedAt` | `timestamp` | ✅ | |
| `closedAt` | `timestamp` | — | |
| `createdAt` | `timestamp` | ✅ | |
| `updatedAt` | `timestamp` | ✅ | |

---

## 6. ResponseAction

An immutable audit record for every action proposed, validated, executed, or rejected. Never updated after creation.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string (uuid)` | ✅ | |
| `caseId` | `string (uuid)` | ✅ | FK → Case.id |
| `identityId` | `string (uuid)` | ✅ | FK → Identity.id (subject of the action) |
| `actionType` | `enum` | ✅ | `session_revoke`, `mfa_stepup`, `conditional_access_update`, `recommendation_only` |
| `source` | `enum` | ✅ | `autopilot`, `analyst` (who triggered the action) |
| `status` | `enum` | ✅ | `proposed`, `validated`, `executed`, `rejected`, `reverted` |
| `rejectionReason` | `string` | — | Why the policy validator rejected the action (if `status = rejected`) |
| `targetSessionId` | `string (uuid)` | — | Session acted upon (for session_revoke) |
| `policyChange` | `object` | — | Structured description of the policy change applied (for conditional_access_update) |
| `executedAt` | `timestamp` | — | When action was executed at target system |
| `executionResult` | `enum` | — | `ok`, `error`, `partial` |
| `executionError` | `string` | — | Error detail if executionResult = error |
| `revertedAt` | `timestamp` | — | If the action was reverted by analyst |
| `revertedBy` | `string` | — | Analyst user ID who reverted |
| `createdAt` | `timestamp` | ✅ | When this record was created |
| `validatedAt` | `timestamp` | — | When policy validator processed the action |

> **Note:** ResponseAction records are immutable. Reverts create a new ResponseAction of type matching the inverse action; the original record is never modified.

---

## 7. OAuthApp *(Optional V1)*

An OAuth application that has been granted access by an identity. Used for OAuth abuse and token scope monitoring.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `string (uuid)` | ✅ | |
| `identityId` | `string (uuid)` | ✅ | FK → Identity.id (who granted access) |
| `appId` | `string` | ✅ | OAuth client ID from source |
| `appName` | `string` | ✅ | Display name of the application |
| `source` | `enum` | ✅ | `okta`, `m365` |
| `scopes` | `string[]` | ✅ | Granted OAuth scopes |
| `grantedAt` | `timestamp` | ✅ | When access was granted |
| `revokedAt` | `timestamp` | — | When access was revoked; null if active |
| `status` | `enum` | ✅ | `active`, `revoked` |
| `riskScore` | `number (0–100)` | — | Risk score for this grant (scope sensitivity × app trust) |
| `createdAt` | `timestamp` | ✅ | |
| `updatedAt` | `timestamp` | ✅ | |
