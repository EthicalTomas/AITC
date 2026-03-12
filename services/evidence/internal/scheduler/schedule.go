// Package scheduler provides a lightweight cron-style scheduler for
// periodic evidence report generation.
package scheduler

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// Job is a function that the scheduler runs on each tick.
// ctx is cancelled when the service shuts down.
type Job func(ctx context.Context) error

// Scheduler runs a Job on a fixed interval until ctx is cancelled.
type Scheduler struct {
	interval time.Duration
	job      Job
	logger   *zap.Logger
}

// New creates a Scheduler that runs job every interval.
func New(interval time.Duration, job Job, logger *zap.Logger) *Scheduler {
	return &Scheduler{interval: interval, job: job, logger: logger}
}

// Run starts the scheduler loop. It blocks until ctx is cancelled.
// The first execution happens after the initial interval elapses (not immediately).
func (s *Scheduler) Run(ctx context.Context) {
	s.logger.Info("scheduler started", zap.Duration("interval", s.interval))
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("scheduler stopped")
			return
		case t := <-ticker.C:
			s.logger.Info("scheduler tick", zap.Time("at", t))
			if err := s.job(ctx); err != nil {
				s.logger.Error("scheduler job failed", zap.Error(err))
			}
		}
	}
}

// RunNow executes the job immediately in the current goroutine and returns.
// It is used for on-demand mode.
func (s *Scheduler) RunNow(ctx context.Context) error {
	return s.job(ctx)
}

