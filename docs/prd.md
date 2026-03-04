# Product Requirements Document — AITC

**Version:** 0.1 (MVP / V1)  
**Status:** Draft  
**Audience:** Engineering, Product, GTM

---

## 1. Problem Statement

Mid-market IT and security teams in regulated industries (finance, healthcare, professional services) face a growing volume of identity-based threats — credential compromise, privilege escalation, OAuth abuse, and insider risk — yet lack the staff and tooling to detect and respond to them quickly. Legacy SIEM and UEBA tools require months of tuning, produce too much noise, and cannot autonomously act to contain threats.

AITC provides **Autonomous Identity Threat Containment for Regulated SaaS**: an identity-first, AI-native platform that continuously scores every identity, detects anomalies, and — once trusted — automatically executes safe containment actions within a strict guardrail framework.

---

## 2. Target User

**Primary buyer:** Mid-market IT and Security (500–5,000 employees), operating in regulated environments (SOC 2, ISO 27001, HIPAA, PCI-DSS adjacent).

**Primary personas:**

| Persona | Description |
|---|---|
| **IT/Security Manager** | Owns the security stack; wants fewer alerts and faster response with evidence for auditors |
| **Identity Engineer** | Manages Okta and M365; wants automation for identity incidents without risky account actions |
| **Compliance Officer** | Needs continuous audit evidence; wants automated compliance reports |

---

## 3. Positioning

> **Autonomous Identity Threat Containment for Regulated SaaS.**

AITC differentiates by combining:
- Identity-first data model across SSO (Okta) and productivity SaaS (M365)
- Continuous Authentication Score (CAS) per identity
- Bounded AI reasoning for case enrichment
- Safe, allowlisted autonomous response with a hard guardrail framework
- Compliance-by-design: SOC 2 + ISO 27001 automation built in

---

## 4. Scope

### 4.1 In Scope — MVP / V1

- **Ingestion:** Okta System Log API (polling + backfill) and Microsoft 365 Unified Audit Log (UAL) polling
- **Control plane (enforcement):** Okta only (V1)
- **Risk scoring:** Continuous Authentication Score (CAS) per identity
- **Autonomy:** Recommend-only for first 7 days (learning mode), then safe auto-remediation (autopilot)
- **Safe auto-remediation actions:**
  - Session revocation (Okta)
  - MFA step-up trigger (Okta)
  - Scoped conditional access adjustment (Okta sign-on policy)
- **Compliance:** SOC 2 + ISO 27001 evidence generation and reporting
- **Deployment:** SaaS, US-only

### 4.2 Non-Goals (V1)

- Account deletion (explicitly disallowed — see §7)
- Device isolation or EDR-triggered actions
- Production workload shutdown
- Multi-region deployment (post-V1)
- Hybrid/on-premises connector (optional, post-V1)
- Event Hooks ingestion from Okta (Phase 2)
- Google Workspace, Salesforce, or other SaaS integrations (Phase 2+)

---

## 5. Success Metrics

| Metric | Target |
|---|---|
| Time-to-detect (TTD) | < 5 minutes from event to CAS update for Okta events |
| Time-to-contain (TTC) — autopilot | < 60 seconds from case open to action executed |
| False positive rate | < 5% for autopilot-executed actions after learning mode |
| Compliance report generation | On-demand, < 30 seconds |
| Customer onboarding to first detection | < 1 business day |
| Okta System Log polling latency | 30–60 seconds target |
| M365 UAL polling latency | 5–15 minutes typical (lower end on E5, higher end on E3/lower tiers; platform-imposed) |

---

## 6. Integrations — V1

### 6.1 Okta (System Log API)

- **Ingestion method:** REST polling of `/api/v1/logs` with since/until watermarking; backfill on first connection
- **Phase 2:** Replace or supplement polling with Okta Event Hooks for near-real-time delivery
- **Control plane:** AITC sends remediation actions to Okta via Management API (session revoke, policy update, MFA push)
- **Auth:** Okta API token scoped to read logs + policy management; stored in secrets manager

### 6.2 Microsoft 365 (Unified Audit Log)

- **Ingestion method:** UAL polling via `Search-UnifiedAuditLog` / Graph `security/auditLogs` with watermarking; typical availability lag 5–15 minutes (lower end on E5 licensing, higher end on E3/lower tiers)
- **Scope (V1):** Azure AD sign-in logs, Exchange Online mailbox rules, SharePoint/OneDrive file access, Teams messages (metadata only)
- **Control plane (V1):** Read-only; no enforcement actions via M365 in V1

---

## 7. Autonomy Ladder

AITC progresses through two autonomy states after onboarding:

```
Day 0–7: LEARNING MODE
  - AITC ingests events, builds behavioral baselines, scores identities
  - All risk detections surface as recommendations only
  - No automated response actions executed
  - Human analyst must approve any action

Day 8+: AUTOPILOT
  - AITC executes allowlisted safe actions autonomously for high-confidence, high-severity cases
  - All actions logged with full audit trail (who, what, when, why)
  - Analyst receives real-time notification; can revert within grace window
  - Escalation cases (uncertain or novel) always go to human review queue
```

### 7.1 Allowed Actions (V1 Autopilot)

| Action | Mechanism | Notes |
|---|---|---|
| Session revocation | Okta Management API | Terminates all active sessions for the identity |
| MFA step-up trigger | Okta Sign-On Policy | Forces additional factor on next authentication |
| Scoped conditional access | Okta Sign-On Policy adjustment | Restricts sign-on conditions (IP, device, time) |

### 7.2 Explicitly Disallowed Actions (Hard Guardrails)

The following actions are **permanently blocked** by the policy/action validator and cannot be enabled by configuration:

| Disallowed Action | Reason |
|---|---|
| Account deletion / deprovisioning | Irreversible; high blast radius |
| Device isolation (MDM/EDR) | Out of scope for identity plane; requires separate approval chain |
| Production workload / service shutdown | Catastrophic operational risk |
| Broad firewall or network block rules | Network-layer action outside identity control plane |
| Bulk policy changes affecting > N users | Requires human approval; N configurable, default 5 |

### 7.3 LLM Reasoning Guardrail

The bounded LLM reasoning service enriches case narratives and generates human-readable recommendations. It operates under a strict allowlist:

- **Cannot** directly call action executors or Okta/M365 APIs
- **Cannot** modify risk scores or case status directly
- All LLM outputs are passed through the policy/action validator before any effect
- LLM is used only for: narrative generation, anomaly explanation, recommended next steps

---

## 8. MVP vs V1 Roadmap

| Capability | MVP | V1 |
|---|---|---|
| Okta System Log polling | ✅ | ✅ |
| M365 UAL polling | ✅ | ✅ |
| CAS per identity | ✅ | ✅ |
| Learning mode (recommend-only, 7 days) | ✅ | ✅ |
| Autopilot (session revoke, MFA step-up) | — | ✅ |
| Scoped conditional access (Okta policy) | — | ✅ |
| Case management console | Basic | Full |
| SOC 2 / ISO 27001 reports | — | ✅ |
| Okta Event Hooks ingestion | — | — (Phase 2) |
| M365 enforcement actions | — | — (Phase 2) |
| Hybrid connector | — | — (Phase 2) |
| Multi-region | — | — (Phase 2) |

---

## 9. Deployment Constraints

- **SaaS-first:** AITC is delivered as a cloud-hosted SaaS product
- **US-only (V1):** Data residency and processing limited to US regions only; no cross-border data transfer
- **Hybrid connector (Phase 2):** Optional lightweight connector for on-premises AD or private network log sources
- **Multi-region (Phase 2):** EU and APAC regions planned post-V1
