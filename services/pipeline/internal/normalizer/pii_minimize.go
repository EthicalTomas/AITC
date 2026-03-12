// Package normalizer — PII minimization helpers.
// SECURITY: Call MinimizePII before writing to logs or non-secure sinks.
// Raw normalized events with PII are stored in Postgres (tenant-isolated, RLS-protected).
package normalizer

import (
"strings"

eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
)

const redactedMark = "[REDACTED]"

// MinimizePII returns a shallow copy of ev with PII fields redacted for safe logging.
// The original is not modified. Persist the original to secure storage.
func MinimizePII(ev *eventspb.NormalizedEventV1) *eventspb.NormalizedEventV1 {
if ev == nil {
return nil
}
copy := *ev
copy.ActorEmail = redactEmail(copy.ActorEmail)
copy.SourceIp = redactIP(copy.SourceIp)
// Retain geo at country level; drop city for lower PII surface.
copy.GeoCity = ""
return &copy
}

// redactEmail replaces the local part of an email with [REDACTED].
// "alice@example.com" → "[REDACTED]@example.com"
func redactEmail(email string) string {
if email == "" {
return ""
}
at := strings.LastIndex(email, "@")
if at < 0 {
return redactedMark
}
return redactedMark + email[at:]
}

// redactIP replaces an IP address with [REDACTED].
func redactIP(ip string) string {
if ip == "" {
return ""
}
return redactedMark
}
