package scheduler_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/ethicaltomas/aitc/services/evidence/internal/scheduler"
)

func TestScheduler_RunNow_Success(t *testing.T) {
	var called int32
	sched := scheduler.New(time.Minute, func(ctx context.Context) error {
		atomic.AddInt32(&called, 1)
		return nil
	}, zap.NewNop())

	if err := sched.RunNow(context.Background()); err != nil {
		t.Fatalf("RunNow: %v", err)
	}
	if atomic.LoadInt32(&called) != 1 {
		t.Errorf("expected job called once, got %d", atomic.LoadInt32(&called))
	}
}

func TestScheduler_RunNow_PropagatesError(t *testing.T) {
	sentinel := errors.New("job error")
	sched := scheduler.New(time.Minute, func(ctx context.Context) error {
		return sentinel
	}, zap.NewNop())

	if err := sched.RunNow(context.Background()); !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

func TestScheduler_Run_StopsOnContextCancel(t *testing.T) {
	var called int32
	sched := scheduler.New(10*time.Millisecond, func(ctx context.Context) error {
		atomic.AddInt32(&called, 1)
		return nil
	}, zap.NewNop())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Run blocks until ctx is cancelled; should return promptly.
	done := make(chan struct{})
	go func() {
		sched.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Good.
	case <-time.After(500 * time.Millisecond):
		t.Error("scheduler did not stop after context cancellation")
	}

	if atomic.LoadInt32(&called) == 0 {
		t.Error("expected job to be called at least once during 50ms window")
	}
}
