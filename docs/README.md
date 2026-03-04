# AITC Documentation Index

**AITC — Autonomous Identity Threat Containment for Regulated SaaS**

This directory contains all product, architecture, data model, and compliance documentation for the AITC platform.

---

## Documents

| Document | Description |
|---|---|
| [Product Requirements (PRD)](./prd.md) | Problem statement, target user, MVP scope, autonomy ladder, guardrails, and success metrics |
| [Architecture](./architecture.md) | High-level system architecture, service components, dataflow diagrams, and latency targets |
| [Data Model — Overview](./datamodel/overview.md) | Core design principles, entity relationships, and identity-centric model summary |
| [Data Model — Entities](./datamodel/entities.md) | Canonical entity definitions: Identity, Session, Event, RiskSignal, Case, ResponseAction, OAuthApp |
| [Data Model — Events](./datamodel/events.md) | Normalized event taxonomy across Okta and Microsoft 365 |
| [Data Model — JSON Schema v1](./datamodel/schemas/v1.entities.json) | Machine-readable schema document for all V1 entities |
| [Compliance Pack — SOC 2 + ISO 27001](./compliance/soc2-iso-pack.md) | Evidence artifacts, control mappings, audit trails, and report generation |

---

## Terminology

| Term | Definition |
|---|---|
| **AITC** | Autonomous Identity Threat Containment — the platform name |
| **CAS** | Continuous Authentication Score — the real-time per-identity risk score |
| **Learning mode** | First 7 days post-onboarding; AITC recommends actions but does not execute them automatically |
| **Autopilot** | Post-learning-mode state; AITC executes safe, allowlisted response actions autonomously |
| **LLM reasoning service** | Bounded large-language-model service used for case narrative and recommendation enrichment; cannot directly execute actions |
