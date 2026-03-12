// Package main implements the enforcement-okta service entry point.
// It consumes action-requests from Kafka, checks idempotency, enforces the
// policy allowlist, and executes safe Okta actions with full audit logging.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ethicaltomas/aitc/internal/config"
	enforcementokta "github.com/ethicaltomas/aitc/services/enforcement_okta"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "enforcement-okta: fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "configs/env/enforcement-okta.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	return enforcementokta.Run(cfg)
}

