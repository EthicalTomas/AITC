# How to work the path: release loops that compound

## 1) Release strategy: “Design Partner → GA → Expand”
### Stage A — Design Partner (DP) release (v1)
Ship to ~3–10 organizations that match your ICP (Okta + M365, regulated, mid-market).
Goal: validate
- signal quality (noise vs value)
- autonomy safety (no lockouts, no chaos)
- evidence/report usefulness
- time-to-value (hours/days, not months)

DP success criteria (hard gates):
- learning mode enforced and understood
- recommendations are useful in week 1
- autopilot safe actions work after day 8
- clear audit trail and evidence exports
- low operational burden to deploy

### Stage B — “Limited GA” (v1.1 / v1.2)
After DP, tighten:
- stability, performance, onboarding, docs
- pricing packaging
- reliability (retries, DLQs, backfills, dashboards)
Then expand to ~20–50 customers.

### Stage C — “New pillar” releases (v2, v3…)
Each major phase in the roadmap should add one *pillar* at a time:
- v2: Cloud control plane (CloudTrail/Azure)
- v3: Endpoint sensor
- v4: Network telemetry
- v5: cross-customer learning / TI graph
This prevents SKU sprawl and keeps one console + one model.

## 2) How often to “put it out again”
You don’t need big relaunches every time. Use two release rhythms:

- Continuous: weekly/biweekly patches (bugfix, tuning, UX, reliability)
- Milestone: quarterly “pillar” releases (new data domain + new value)

## 3) The autonomy maturity loop (safe iteration model)
For each new capability, repeat:
1) Ingest + normalize
2) Detect (recommend-only)
3) Validate with DP customers (false positive review)
4) Add guardrails + simulation + blast radius controls
5) Enable autopilot only for safe actions
6) Expand actions gradually

This is how you reach “near-zero SOC intervention” without breaking customers.

## 4) Practical product packaging (avoids SKU sprawl)
Avoid selling “Okta SKU”, “M365 SKU”, etc.
Instead sell:
- Platform (single agent + console + model)
- Data connectors included by default (within reasonable limits)
- Transparent scaling dimensions:
  - protected identities
  - endpoints (when you add them)
  - ingestion volume / retention
  - autopilot tiers by action class

## 5) What NOT to do
- Don’t wait for endpoint/network/OT/global graph to be done before selling.
- Don’t enable broad autopilot early; it will destroy trust.
- Don’t add multiple data models per pillar; unify into the canonical model.

## 6) A concrete “loop” you can run starting now
- Month 0–2: DP v1 (Okta + M365 + safe autopilot + evidence)
- Month 2–3: v1.1 hardening + onboarding + pricing + dashboards
- Month 3–6: v2 CloudTrail pillar (still one console/model)
- Month 6–9: v3 Endpoint sensor pillar
