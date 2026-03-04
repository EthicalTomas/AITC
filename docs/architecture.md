# AITC — High-Level Architecture

**Version:** 0.1  
**Status:** Draft

---

## 1. Overview

AITC is a cloud-native, identity-first SaaS platform deployed in US regions (V1). It ingests identity and audit events from Okta and Microsoft 365, normalizes them into a unified data model, computes per-identity Continuous Authentication Scores (CAS), opens cases for anomalies, and — after learning mode — autonomously executes safe containment actions via the Okta control plane.

---

## 2. Component Inventory

| Component | Responsibility |
|---|---|
| **Ingestion Service** | Polls Okta System Log API and M365 UAL on scheduled intervals; manages watermarks and backfill |
| **Normalization / Entity Resolution** | Maps raw events to the canonical AITC event schema; resolves identity across sources (email, UPN, Okta UID) |
| **Unified Data Store** | Append-only event store (immutable log); queryable by identity, session, time range |
| **Feature Store** | Per-identity behavioral features updated incrementally: login velocity, geo spread, device count, hour-of-day distribution, etc. |
| **Risk Engine (CAS)** | Computes the Continuous Authentication Score per identity using feature vectors and rule/ML models; produces RiskSignal records |
| **Case Management** | Opens, enriches, routes, and closes cases; maintains case timeline; exposes case API to console |
| **Policy / Action Validator** | Enforces the action allowlist and hard guardrails; validates every proposed action before execution; blocks disallowed actions unconditionally |
| **Action Executors (Okta)** | Calls Okta Management API for: session revoke, MFA step-up, sign-on policy scoped update |
| **Audit Logger** | Writes an immutable audit record for every action proposed, validated, executed, or rejected; used for compliance exports |
| **LLM Reasoning Service** | Bounded LLM service; enriches case narratives and generates human-readable recommendations; cannot directly call action executors or modify data |
| **Console / UI** | Case queue, identity profile, risk timeline, recommendation review, audit log viewer, report center |
| **Reporting Service** | Generates on-demand and scheduled compliance reports (SOC 2, ISO 27001) from audit log and case data |
| **Graph Store** *(Phase 2)* | Stores identity-to-identity, identity-to-resource relationships; used for blast radius analysis |
| **Hybrid Connector** *(Phase 2)* | Lightweight agent for on-premises AD / private log sources; forwards normalized events to ingestion service |

---

## 3. Dataflow Diagram

### 3.1 Main Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│  External Sources                                               │
│                                                                 │
│  ┌───────────────────┐       ┌─────────────────────────────┐   │
│  │  Okta System Log  │       │  Microsoft 365 UAL          │   │
│  │  (REST polling)   │       │  (Graph / PS polling)       │   │
│  │  30–60s target    │       │  5–15 min typical           │   │
│  └────────┬──────────┘       └────────────┬────────────────┘   │
└───────────│──────────────────────────────│────────────────────┘
            │                              │
            ▼                              ▼
┌───────────────────────────────────────────────────────────────┐
│  Ingestion Service                                            │
│  • Watermark management (since/until cursors per source)      │
│  • Backfill on first connection                               │
│  • Deduplication by event ID                                  │
│  • Emits raw events onto internal event bus                   │
└──────────────────────────────┬────────────────────────────────┘
                               │
                               ▼
┌───────────────────────────────────────────────────────────────┐
│  Normalization / Entity Resolution                            │
│  • Maps source event schema → AITC canonical Event schema     │
│  • Resolves identity: email ↔ UPN ↔ Okta UID → Identity.id   │
│  • Extracts session, device, geo, user-agent                  │
│  • Emits normalized Event records                             │
└──────────────────────────────┬────────────────────────────────┘
                               │
                   ┌───────────┴──────────┐
                   ▼                      ▼
┌──────────────────────────┐  ┌──────────────────────────────────┐
│  Unified Data Store      │  │  Feature Store                   │
│  (immutable event log)   │  │  • Per-identity behavioral       │
│  • Queryable by identity │  │    features updated incrementally│
│  • Append-only           │  │  • Login velocity, geo spread,   │
│  • Retained for audit    │  │    device fingerprints, etc.     │
└──────────────────────────┘  └──────────────────┬───────────────┘
                                                 │
                                                 ▼
                               ┌─────────────────────────────────┐
                               │  Risk Engine (CAS)              │
                               │  • Reads feature vectors        │
                               │  • Applies rule + ML models     │
                               │  • Emits CAS score (0–100)      │
                               │  • Writes RiskSignal records     │
                               └──────────────────┬──────────────┘
                                                  │
                                                  ▼
                               ┌─────────────────────────────────┐
                               │  Case Management                │
                               │  • Opens Case on threshold      │
                               │  • Aggregates RiskSignals       │
                               │  • Calls LLM Reasoning Service  │
                               │    for narrative enrichment     │
                               │  • Routes: human queue vs       │
                               │    autopilot queue              │
                               └─────┬────────────────┬──────────┘
                                     │                │
                      (Learning      │                │  (Autopilot
                       mode or       ▼                ▼   mode, high
                       uncertain)  ┌──────┐    ┌──────────────────┐
                                   │Human │    │Policy / Action   │
                                   │Queue │    │Validator         │
                                   │(UI)  │    │• Enforces allow- │
                                   └──────┘    │  list + guardrails│
                                               │• Blocks disallowed│
                                               └────────┬─────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │ Action Executors │
                                               │ (Okta V1)       │
                                               │ • Session revoke │
                                               │ • MFA step-up   │
                                               │ • Policy adjust │
                                               └────────┬────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │  Audit Logger   │
                                               │  (immutable)    │
                                               │  Every action:  │
                                               │  proposed →     │
                                               │  validated →    │
                                               │  executed /     │
                                               │  rejected       │
                                               └────────┬────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │ Reporting       │
                                               │ Service         │
                                               │ On-demand +     │
                                               │ scheduled       │
                                               │ (SOC2/ISO27001) │
                                               └─────────────────┘
```

### 3.2 LLM Reasoning Service Boundary

```
┌────────────────────────────────────────────────────────┐
│  Case Management                                       │
│                                                        │
│  ┌──────────────────────┐                             │
│  │ Case record +        │  ──────request──────►  ┌────┴──────────────────────────┐
│  │ RiskSignal summaries │                        │  LLM Reasoning Service        │
│  │ (no raw PII)         │  ◄──────response─────  │  • Narrative generation       │
│  └──────────────────────┘                        │  • Recommendation text        │
│                                                  │  • Cannot call Okta/M365 APIs │
│  Recommendation stored on Case                   │  • Cannot modify Risk scores  │
│  ↓                                               │  • Output validated before    │
│  Policy/Action Validator                         │    any action is taken        │
│  (enforces guardrails independently)             └───────────────────────────────┘
└────────────────────────────────────────────────────────┘
```

---

## 4. Latency Targets

| Stage | Target | Notes |
|---|---|---|
| Okta System Log polling | 30–60 seconds | Polling interval; Okta Event Hooks (Phase 2) will reduce to < 5s |
| M365 UAL polling | 5–15 minutes | Platform-imposed availability lag (lower end on E5, higher end on E3/lower tiers); watermarking ensures no gaps |
| Event normalization | < 2 seconds per batch | Internal processing |
| CAS update after event | < 30 seconds from ingest | Risk engine consumes normalized events asynchronously |
| Case creation from CAS threshold | < 5 seconds from CAS update | Case manager subscribes to risk engine output |
| Autopilot action execution | < 60 seconds from case open | Policy validator + action executor |
| Audit record write | Synchronous with action | Before action confirmation returned to caller |

---

## 5. Deployment Architecture (V1)

```
┌──────────────────────────────────────────────────────────────┐
│  AITC SaaS — US Region (V1)                                  │
│                                                              │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐  │
│  │  Ingestion    │  │  Risk Engine  │  │  Console / API  │  │
│  │  Service      │  │  (CAS)        │  │  Gateway        │  │
│  └───────┬───────┘  └───────┬───────┘  └────────┬────────┘  │
│          │                  │                   │            │
│  ┌───────▼──────────────────▼───────────────────▼─────────┐  │
│  │  Internal Event Bus / Message Queue                     │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────┐  ┌───────────────┐  ┌────────────────┐   │
│  │  Data Store  │  │  Feature Store│  │  Audit Log     │   │
│  │  (events)    │  │  (features)   │  │  (immutable)   │   │
│  └──────────────┘  └───────────────┘  └────────────────┘   │
│                                                              │
│  ┌──────────────┐  ┌───────────────┐                        │
│  │  Case Mgmt   │  │  LLM Service  │                        │
│  │              │  │  (bounded)    │                        │
│  └──────────────┘  └───────────────┘                        │
└──────────────────────────────────────────────────────────────┘
         │  outbound API calls only
         ▼
┌────────────────────┐    ┌─────────────────────┐
│  Okta (customer    │    │  Microsoft 365       │
│  tenant)           │    │  (customer tenant)   │
│  Read: System Log  │    │  Read: UAL           │
│  Write: Mgmt API   │    │  Write: V1 none      │
└────────────────────┘    └─────────────────────┘
```

### 5.1 Phase 2 Additions

- **Hybrid Connector:** Lightweight agent deployed in customer network; forwards normalized events to AITC ingestion service over mTLS; no inbound connectivity required
- **Graph Store:** Relationship graph (identity ↔ resource ↔ app); blast radius analysis
- **Multi-region:** EU, APAC regions with data residency controls
- **Okta Event Hooks:** Replace/supplement polling for near-real-time Okta event delivery

---

## 6. Security Architecture Principles

- All inter-service communication uses mutual TLS (mTLS) internally
- Customer credentials (Okta API token, M365 credentials) stored in secrets manager; never logged
- Audit log is append-only; write path separated from read path
- LLM service operates in network-isolated environment; no direct internet or customer API access
- All data at rest encrypted (AES-256); all data in transit encrypted (TLS 1.2+)
- US-only data residency enforced at storage and processing layer (V1)
