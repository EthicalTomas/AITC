// Package autonomy implements the autonomy state machine for the controlplane service.
// CircuitBreaker monitors failure rates and halts autopilot execution when thresholds
// are exceeded, preventing runaway automated actions (Step 0.2 safety net).
package autonomy

import (
	"fmt"
	"sync"
	"time"
)

// CircuitState represents the current circuit breaker state.
type CircuitState int

const (
	// CircuitClosed is the normal operating state — actions may proceed.
	CircuitClosed CircuitState = iota
	// CircuitOpen is the tripped state — actions are halted.
	CircuitOpen
)

// CircuitBreaker halts autopilot when too many action failures occur within a window.
// Thread-safe.
type CircuitBreaker struct {
	mu              sync.Mutex
	state           CircuitState
	failures        int
	lastFailure     time.Time
	threshold       int           // failures before trip
	window          time.Duration // rolling window
	cooldown        time.Duration // open → closed cooldown
	openedAt        time.Time
}

// NewCircuitBreaker creates a CircuitBreaker with the given threshold and cooldown.
// threshold: number of failures in window before tripping.
// window: duration over which failures are counted.
// cooldown: how long to stay open before allowing retry.
func NewCircuitBreaker(threshold int, window, cooldown time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		window:    window,
		cooldown:  cooldown,
		state:     CircuitClosed,
	}
}

// Allow returns nil if an action may proceed, or an error if the circuit is open.
func (cb *CircuitBreaker) Allow() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == CircuitOpen {
		if time.Since(cb.openedAt) >= cb.cooldown {
			// Cooldown expired: reset
			cb.state = CircuitClosed
			cb.failures = 0
		} else {
			return fmt.Errorf(
				"circuit breaker open: too many action failures (cooldown expires in %s)",
				(cb.cooldown - time.Since(cb.openedAt)).Round(time.Second),
			)
		}
	}
	return nil
}

// RecordSuccess resets the failure counter (a successful action restores confidence).
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
}

// RecordFailure increments the failure counter and trips the circuit if threshold is exceeded.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	// Reset counter if outside the rolling window
	if now.Sub(cb.lastFailure) > cb.window {
		cb.failures = 0
	}
	cb.failures++
	cb.lastFailure = now

	if cb.failures >= cb.threshold && cb.state == CircuitClosed {
		cb.state = CircuitOpen
		cb.openedAt = now
	}
}

// State returns the current circuit state (for monitoring/logging).
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

