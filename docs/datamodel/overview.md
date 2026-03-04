# Data Model — Overview

**Version:** 0.1  
**Status:** Draft

---

## 1. Design Principles

### 1.1 Identity-Centric

Every record in the AITC data model anchors to an **Identity**. Events, sessions, risk signals, cases, and response actions all carry a canonical `identityId` that resolves across source systems (Okta UID, Azure AD Object ID, email/UPN).

### 1.2 Single Unified Model

Regardless of source (Okta, Microsoft 365, or future integrations), all data is normalized into the same canonical schema before storage. Source-specific fields are preserved in a structured `raw` envelope for auditability but are never used in risk scoring or compliance reporting directly.

### 1.3 Append-Only Event Log

The event store is **immutable and append-only**. Events are never updated or deleted (outside of legal hold / GDPR erasure workflows, which are handled separately). This guarantees a tamper-evident timeline for compliance and forensic purposes.

### 1.4 Auditability by Design

Every action AITC proposes or executes produces an immutable **ResponseAction** record in the audit log. The full chain — detection → risk signal → case → recommendation → validation → execution — is reconstructable from stored records.

### 1.5 Compliance-Exportable

All entities carry `createdAt` / `updatedAt` timestamps in UTC ISO 8601. Cases and ResponseActions carry references enabling point-in-time reconstruction for SOC 2 and ISO 27001 evidence exports.

---

## 2. Core Entities

| Entity | Purpose |
|---|---|
| **Identity** | Canonical cross-source identity record (person or service account) |
| **Session** | A single authenticated session for an identity at a point in time |
| **Event** | A normalized, canonical record of something that happened (auth, admin change, SaaS action, etc.) |
| **RiskSignal** | A scored anomaly signal produced by the Risk Engine, anchored to an identity |
| **Case** | An investigation record grouping one or more RiskSignals requiring attention |
| **ResponseAction** | A proposed or executed containment action; immutable audit record |
| **OAuthApp** *(optional V1)* | An OAuth application granted access by an identity; used for OAuth abuse detection |

---

## 3. Entity Relationships

```
                        ┌─────────────────┐
                        │    Identity     │
                        │  (canonical)    │
                        └──────┬──────────┘
                    ┌──────────┼──────────────┐
                    │          │              │
                    ▼          ▼              ▼
               ┌─────────┐ ┌──────────┐ ┌──────────┐
               │ Session │ │  Event   │ │OAuthApp  │
               └────┬────┘ └────┬─────┘ └──────────┘
                    │           │
                    └─────┬─────┘
                          │
                          ▼
                   ┌─────────────┐
                   │ RiskSignal  │
                   └──────┬──────┘
                          │  (1 or more per Case)
                          ▼
                   ┌─────────────┐
                   │    Case     │
                   └──────┬──────┘
                          │  (1 or more per Case)
                          ▼
                   ┌──────────────────┐
                   │  ResponseAction  │
                   │  (audit record)  │
                   └──────────────────┘
```

---

## 4. Source Identity Mapping

AITC resolves identities across sources using a deterministic merge strategy:

1. **Primary key:** Normalized email address (lowercased)
2. **Secondary keys:** Okta UID (`okta_uid`), Azure AD Object ID (`aad_oid`), UPN
3. **Conflict resolution:** First-seen source is authoritative for display name; all source IDs stored in `externalIds` map
4. **Service accounts:** Identified by naming convention or manual tagging; still anchored to Identity entity with `accountType: service`

---

## 5. Data Retention

| Data Type | Default Retention | Notes |
|---|---|---|
| Raw events | 90 days | Configurable; raw envelope only |
| Normalized events | 1 year | Required for compliance baseline |
| RiskSignals | 1 year | |
| Cases + ResponseActions | 3 years | SOC 2 / ISO 27001 evidence |
| Audit log (immutable) | 3 years | Cannot be shortened below minimum |
| Feature Store | Rolling 90-day window | Rebuilt from event log on demand |
