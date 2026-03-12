# Version roadmap from v1 → “Autonomous AI Security Standard”
You can do this in **~10 major versions** (v1 through v10) if you keep each version focused on adding **one new pillar** (one data domain + one autonomy expansion + one trust/evidence increment). Each version can have multiple minor releases (v2.1, v2.2…) for hardening.

Below is the cleanest sequencing that covers *all* characteristics you listed with the least rework and least SKU sprawl.

---

## v1 — Identity/SaaS autonomous containment (your current AITC wedge)
**Newly implemented (must-have):**
- Okta System Log + M365 UAL ingestion, normalization into one canonical model
- CAS scoring + case engine + recommendation generation
- 7-day learning mode gate, autopilot OFF by default, safe allowlisted actions only
- Okta enforcement executor: session revoke, MFA step-up, scoped sign-on policy changes
- Immutable audit log + evidence pack generator (SOC2/ISO oriented)
- Single console/API for identities, cases, recommendations, reports

**Characteristics satisfied:** early “fully autonomous” (limited), identity-first (partial), single console/model (within scope), shift-left (not yet), AI-first (bounded)

---

## v2 — Cloud control plane pillar (AWS/Azure/GCP audit logs)
**Newly implemented:**
- CloudTrail + Azure Activity Logs + GCP Audit Logs ingestion + normalization
- Entity resolution: map cloud principals ↔ identities (Okta/M365) where possible
- Cloud risk rules: unusual API calls, new access keys, privilege escalation indicators
- Safe cloud response actions (guardrailed): disable a single access key, force re-auth/step-up, scoped policy tightening (no “account deletion”)

**Adds:** “unified data fabric” expands beyond SaaS to cloud

---

## v3 — Endpoint sensor pillar (single agent begins)
**Newly implemented:**
- Lightweight endpoint agent/collector (start with Linux + Windows minimum set)
  - process start, network connections, login/session, basic file write metadata
- Remote configuration + agent identity + signed updates
- Endpoint-to-identity correlation (device ↔ user ↔ session)
- New detections: token theft indicators, suspicious processes, impossible-travel corroboration
- Autopilot (optional) safe endpoint actions **only if reversible/low-risk** (start recommend-only)

**Adds:** “single agent” begins, unified fabric includes endpoint

---

## v4 — Network telemetry pillar (cloud + on-prem integrations)
**Newly implemented:**
- VPC flow logs + DNS logs + firewall logs ingestion
- Canonical `NetworkFlow` + `DNSQuery` model
- Detections: data exfil patterns, beaconing, rare destinations per identity/device
- Network-aware correlation in cases (identity → device → flows)

**Adds:** unified fabric includes network domain

---

## v5 — Real-time adaptive security engine (closed-loop policy)
**Newly implemented:**
- Risk-aware policy engine: dynamic step-up / conditional access templates
- Policy simulation + blast radius estimation before execution
- Circuit breakers: action-storm protection, confidence thresholds, degradation modes
- Autonomy tiers (per tenant): recommend-only → safe autopilot → expanded autopilot

**Adds:** “real-time adaptive security” becomes real (with safety)

---

## v6 — AI-first deepening + AI model security (LLM runtime protection)
**Newly implemented:**
- LLM gateway service:
  - tool allowlisting (LLM can only call specific functions)
  - strict schema outputs, jailbreak/prompt-injection filtering
  - per-tenant isolation, zero secret access, redaction and audit logs
- Model supply chain controls:
  - prompt/version registry
  - reproducibility metadata
  - evaluation harness for regressions
- “AI reasoning attestation” attached to cases (why, what data, confidence bounds)

**Adds:** “AI model security” and “native AI-first” credibility

---

## v7 — Cross-customer anonymized learning loops (privacy-first)
**Newly implemented:**
- Opt-in global learning:
  - anonymized feature aggregates (k-anonymity thresholds)
  - tenant boundary guarantees
  - governance controls + auditability
- Global baselines improve:
  - rare admin actions by industry
  - new OAuth abuse patterns
  - emerging phishing kits (via shared indicators)
- Feedback loop UX:
  - analyst labels (“true/false positive”) feed learning safely

**Adds:** cross-customer learning loops and compounding detection quality

---

## v8 — Proprietary threat intelligence graph (TI graph) + attack campaign correlation
**Newly implemented:**
- Threat graph store:
  - IP/domain/cert/ASN entities
  - identity/device/workload/resource entities
  - edges: observed, correlated, causal, similarity clusters
- Correlation engine:
  - cluster cases into campaigns
  - propagate risk across the graph with safeguards
- TI ingestion:
  - open feeds + customer sightings + your own derived indicators

**Adds:** proprietary TI graph, stronger “single data fabric” value

---

## v9 — Predictive attack modeling (anticipatory security)
**Newly implemented:**
- Attack path forecasting:
  - likely next steps given current posture + observed signals
  - “leading indicators” model + confidence scoring
- “Prevent” recommendations:
  - specific actions that reduce predicted path probability
- Automated prevention (optional) with strict simulation and customer approvals for higher-risk actions

**Adds:** predictive modeling vs purely reactive detections

---

## v10 — IoT/OT deep visibility + global sensor footprint + post-quantum readiness
This is the “platform maturity” release; likely multiple sub-versions.

**Newly implemented:**
- OT/IoT:
  - passive discovery sensors or deep integration with OT vendors (Nozomi/Claroty)
  - OT asset inventory + network segmentation insights in the same graph/case model
- Massive global footprint:
  - scalable ingestion plane (multi-region eventual)
  - global reputation + telemetry aggregation (from v7/v8 foundations)
- PQC readiness:
  - cryptographic inventory + migration plan
  - TLS hybrid readiness where applicable
  - KMS/HSM strategy and customer-facing attestations

**Adds:** OT/IoT deep visibility, global scale, PQC readiness

---

# Where “transparent pricing” and “50–70% lower overhead” fit
These are not single-version features; they are outcomes of:
- v1–v3: fast deployment + minimal tuning (low overhead)
- v5: automation with safety (less human SOC work)
- v7+: better global baselines (less tuning/noise)
Pricing strategy should be established at **v1.1–v2** and then kept stable.

---

## Summary: How many versions?
**10 major versions** is the most realistic “complete coverage” plan:
- v1–v4: build the unified fabric across identity/SaaS/cloud/endpoint/network
- v5–v6: make it adaptive + secure the AI runtime
- v7–v9: learning loops + TI graph + predictive modeling
- v10: OT/IoT + massive footprint + PQC readiness

If you want, I can convert this into:
1) a 2-year timeline (quarters) with dependencies, or
2) a “minimum version set” (like 6 versions) that still *claims* most characteristics, but with reduced depth in OT/PQC/global sensors.
