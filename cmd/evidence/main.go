package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ethicaltomas/aitc/internal/config"
	evidence "github.com/ethicaltomas/aitc/services/evidence"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "evidence: fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "configs/env/evidence.yaml", "path to YAML config file")
	tenantID := flag.String("tenant", "", "tenant ID for on-demand report generation")
	reportID := flag.String("report", "", "report ID for on-demand report generation")
	intervalSec := flag.Int("interval", 300, "scheduler poll interval in seconds (scheduled mode)")
	flag.Parse()

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	opts := evidence.Options{
		OnDemandTenantID: *tenantID,
		OnDemandReportID: *reportID,
		ScheduleInterval: time.Duration(*intervalSec) * time.Second,
	}

	return evidence.Run(cfg, opts)
}

