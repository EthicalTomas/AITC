// Package normalizer provides PII minimization for normalized events.
// See security/pii-handling.md for the full policy.
package normalizer

import (
	"net"
	"strings"

	eventspb "github.com/ethicaltomas/aitc/contracts/gen/go/aitc/events"
)

// MinimizePII returns a shallow copy of ev with PII fields redacted or
// minimized according to the AITC PII handling policy:
//   - source_ip: masked to /24 subnet for IPv4 (last octet → 0), or /48 for IPv6.
//   - actor_email: domain preserved, local-part replaced with a prefix + "****".
//   - user_agent: preserved (not PII per policy; useful for fingerprinting).
//
// The original event is not modified.
func MinimizePII(ev *eventspb.NormalizedEventV1) *eventspb.NormalizedEventV1 {
	if ev == nil {
		return nil
	}
	// Shallow copy
	out := *ev
	out.SourceIp = maskIP(ev.GetSourceIp())
	out.ActorEmail = maskEmail(ev.GetActorEmail())
	return &out
}

// maskIP masks IPv4 addresses to the /24 boundary (last octet = 0) and IPv6
// addresses to the /48 boundary. Invalid/empty inputs are returned as-is.
func maskIP(raw string) string {
	if raw == "" {
		return raw
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "[invalid_ip]"
	}
	if ip4 := ip.To4(); ip4 != nil {
		// Mask IPv4 to /24
		masked := ip4.Mask(net.CIDRMask(24, 32))
		return masked.String()
	}
	// IPv6: mask to /48
	masked := ip.Mask(net.CIDRMask(48, 128))
	return masked.String()
}

// maskEmail preserves the email domain and replaces the local part with up to
// 2 visible characters followed by "****". Non-email strings are fully redacted.
func maskEmail(email string) string {
	if email == "" {
		return email
	}
	idx := strings.LastIndex(email, "@")
	if idx <= 0 {
		return "[redacted]"
	}
	local := email[:idx]
	domain := email[idx:]
	visible := 2
	if len(local) < visible {
		visible = len(local)
	}
	return local[:visible] + "****" + domain
}

