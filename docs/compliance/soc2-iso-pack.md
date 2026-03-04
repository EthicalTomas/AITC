# Compliance Pack — SOC 2 + ISO 27001

**Version:** 0.1  
**Status:** Draft  
**Applicability:** AITC V1 — US Region

---

## 1. Overview

AITC is designed with compliance automation as a first-class feature. The platform continuously generates evidence artifacts as a natural by-product of its operations — every detection, recommendation, and autonomous action is recorded in an immutable audit log. These artifacts map directly to SOC 2 Trust Service Criteria (Security, Availability, Confidentiality) and ISO/IEC 27001:2022 Annex A controls.

This document describes:
- What evidence artifacts AITC generates
- How they map to SOC 2 and ISO 27001 controls
- How compliance reports are produced (on-demand and scheduled)

---

## 2. Evidence Artifacts

### 2.1 Continuous Audit Log

The AITC audit log is the foundation of the compliance evidence pack. It is:

- **Append-only and immutable:** Records cannot be modified or deleted within the retention period
- **Timestamped in UTC:** All records carry `createdAt` with millisecond precision
- **Identity-anchored:** Every record resolves to a canonical Identity ID
- **Complete lifecycle coverage:** Records every stage — event ingest → risk signal → case open → recommendation → policy validation → action execution / rejection

#### Audit Log Record Types

| Record Type | What It Captures |
|---|---|
| `aitc.risk.signal_created` | Which anomaly was detected, for which identity, with CAS score and confidence |
| `aitc.case.opened` | Case opened, severity, routing mode, learning mode status |
| `aitc.action.proposed` | Action type, source (autopilot or analyst), target identity and session |
| `aitc.action.validated` | Policy validator passed; allowlist check passed |
| `aitc.action.rejected` | Policy validator blocked the action; rejection reason recorded |
| `aitc.action.executed` | Action sent to target system; outcome (ok / error / partial) recorded |
| `aitc.action.reverted` | Action reverted by analyst; who reverted and when |
| `aitc.case.closed` | Case resolution, final status, closure reason |

### 2.2 Identity Incident Timeline

For each Case, AITC can produce a point-in-time reconstructed **incident timeline** showing:

1. Raw events ingested from source systems (Okta, M365) with source timestamps
2. Normalization and entity resolution decisions
3. RiskSignals generated, including feature snapshot and model confidence
4. CAS score changes over the incident window
5. Case opening, assignment, and routing decision (human vs. autopilot)
6. LLM-generated recommendation (with bounded reasoning attestation)
7. All ResponseActions: proposed → validated/rejected → executed/reverted
8. Final case resolution

This timeline is exportable as JSON (for programmatic use) and PDF (for auditor delivery).

### 2.3 Actions Executed Report

A structured listing of all autonomous and analyst-initiated actions executed within a time range:

| Field | Description |
|---|---|
| `actionId` | ResponseAction.id |
| `caseId` | Linked Case.id |
| `actionType` | Type of action (session_revoke, mfa_stepup, conditional_access_update) |
| `identityId` | Subject identity |
| `triggeredBy` | `autopilot` or analyst name |
| `executedAt` | Timestamp of execution |
| `executionResult` | ok / error / partial |
| `revertedAt` | If reverted, timestamp and reverting analyst |

This report is produced on-demand for any date range and is included in scheduled monthly compliance exports.

### 2.4 Identity Risk Summary Report

Aggregated per-identity risk posture over a time window:

- CAS score trend (daily average)
- Number of RiskSignals generated
- Number of Cases opened and resolved
- Actions taken on the identity
- Current autonomy state (learning mode or autopilot)

### 2.5 Policy Change Log

All changes to Okta sign-on policies made by AITC are logged with:

- Before/after policy state snapshot
- Linked Case and ResponseAction IDs
- Whether change was autonomous or analyst-approved
- Timestamp and execution result

---

## 3. SOC 2 Control Mapping

AITC generates evidence for the following SOC 2 Trust Service Criteria (TSC):

### CC6 — Logical and Physical Access Controls

| Control Objective | AITC Evidence |
|---|---|
| CC6.1 — Logical access security measures | Identity inventory with role/group membership; OAuth grant log |
| CC6.2 — New internal user access | `admin_change.user.created` events; `admin_change.role.assigned` events; onboarding timeline |
| CC6.3 — Remove access for terminated users | `admin_change.user.deactivated`; `auth.session.revoked` actions tied to offboarding cases |
| CC6.6 — Logical access restrictions | `conditional_access_update` ResponseActions with policy change log; MFA enrollment status per identity |
| CC6.7 — Transmission of data | TLS enforcement logs (infrastructure layer; separate evidence) |
| CC6.8 — Prevention of unauthorized access | CAS anomaly detection; session revocation audit trail; MFA step-up trigger log |

### CC7 — System Operations

| Control Objective | AITC Evidence |
|---|---|
| CC7.2 — Monitor for security threats | Continuous CAS scoring; RiskSignal records with detection timestamps; alert-to-case pipeline audit |
| CC7.3 — Evaluate security threats | Case investigation records; LLM recommendation attestation |
| CC7.4 — Respond to identified threats | ResponseAction audit trail; actions executed report; incident timeline export |
| CC7.5 — Identify and remediate vulnerabilities | OAuth scope monitoring; privileged role assignment alerts |

### CC9 — Risk Mitigation

| Control Objective | AITC Evidence |
|---|---|
| CC9.1 — Risk mitigation activities | Autopilot action audit trail; guardrail enforcement log (rejected actions) |
| CC9.2 — Business disruption risk | Guardrail enforcement: account deletion and service shutdown permanently blocked; log of all rejections |

### A1 — Availability

| Control Objective | AITC Evidence |
|---|---|
| A1.2 — Environmental protections and recovery | Ingestion watermark state log; backfill completion records |

---

## 4. ISO/IEC 27001:2022 Control Mapping

AITC generates evidence for the following ISO 27001 Annex A controls:

| ISO 27001 Control | Control Title | AITC Evidence |
|---|---|---|
| A.5.15 | Access control | Identity inventory; group/role membership events; OAuth grant log |
| A.5.16 | Identity management | Cross-source identity resolution log; `externalIds` mapping |
| A.5.17 | Authentication information | MFA enrollment status; password change events; session start/end records |
| A.5.18 | Access rights | Role assignment events (`admin_change.role.assigned`); quarterly access report |
| A.5.26 | Response to information security incidents | Case records; incident timeline export; ResponseAction audit trail |
| A.5.27 | Learning from information security incidents | Case resolution notes; false positive tracking; signal tuning log |
| A.5.28 | Collection of evidence | Immutable audit log; incident timeline; raw event preservation (90 days) |
| A.8.2  | Privileged access rights | Privileged role assignment/removal events; CAS elevation signals |
| A.8.5  | Secure authentication | MFA enforcement events; step-up trigger audit; failed auth patterns |
| A.8.15 | Logging | Append-only audit log; ingestion completeness watermark records |
| A.8.16 | Monitoring activities | CAS continuous scoring records; anomaly detection pipeline audit |
| A.8.17 | Clock synchronization | All timestamps in UTC ISO 8601; source event timestamp preserved alongside AITC ingest timestamp |

---

## 5. Report Generation

### 5.1 On-Demand Reports

Available immediately from the AITC console or via API:

| Report | Description | Format |
|---|---|---|
| Incident Timeline | Full audit chain for a specific Case ID | JSON, PDF |
| Actions Executed | All ResponseActions in a date range | CSV, JSON, PDF |
| Identity Risk Summary | Per-identity CAS trend and case history | PDF, JSON |
| Policy Change Log | All AITC-initiated Okta policy changes | CSV, JSON, PDF |
| Guardrail Rejection Log | All actions blocked by policy validator | CSV, JSON |
| OAuth Grant Report | All OAuth grants with scope risk scores | CSV, JSON |

### 5.2 Scheduled Reports

Automatically delivered to configured recipients on a schedule:

| Report | Default Schedule | Format |
|---|---|---|
| Monthly Compliance Summary | 1st of each month | PDF |
| Actions Executed (monthly) | 1st of each month | CSV + PDF |
| Identity Risk Summary (weekly) | Every Monday | PDF |
| SOC 2 Evidence Bundle | Quarterly (or on demand) | ZIP (JSON + PDF) |
| ISO 27001 Evidence Bundle | Quarterly (or on demand) | ZIP (JSON + PDF) |

### 5.3 Report Delivery

- **Console:** Reports available in the AITC reporting center with search and filter
- **API:** `GET /api/v1/reports/{reportType}?from=...&to=...` returns structured JSON or triggers PDF generation
- **Email:** Scheduled reports delivered to configured recipients
- **SIEM / S3 export:** Audit log events can be streamed to customer-controlled S3 bucket or SIEM (Phase 2)

---

## 6. Audit Trail Guarantees

| Guarantee | Implementation |
|---|---|
| Tamper-evident | Audit log is append-only; no update or delete path exists in the write API |
| Completeness | Ingestion watermarks ensure no events are skipped; backfill on reconnect |
| Non-repudiation | Every automated action records the triggering Case, RiskSignal, and policy validation decision |
| Retention | Minimum 3 years for Cases and ResponseActions; 1 year for normalized events |
| Exportability | All records exportable as structured JSON for point-in-time reconstruction |
| Human override accountability | Every analyst action records the analyst user ID; reverts create new immutable records |

---

## 7. Guardrail Enforcement Evidence

The policy/action validator produces a rejection log for every action it blocks. This log serves as evidence that AITC's hard guardrails are operating correctly:

| Field | Description |
|---|---|
| `rejectionId` | Unique rejection record ID |
| `proposedAction` | Action type that was proposed |
| `identityId` | Target identity |
| `caseId` | Linked case |
| `rejectionReason` | Which guardrail rule blocked the action |
| `blockedBy` | `policy_validator` (always system; never bypassed) |
| `timestamp` | UTC timestamp of rejection |

This log is included in the SOC 2 and ISO 27001 evidence bundles as evidence of control operation.
