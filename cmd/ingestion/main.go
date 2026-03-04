// Package main is the ingestion service entry point.
// It loads configuration and delegates to services/ingestion.Run().
//
// # Configuration
//
// Config is loaded from the YAML file specified by -config
// (default: configs/env/ingestion.yaml) with environment variable overrides.
// Set ingestion.mock: true to run against sample data files without calling
// real Okta or M365 APIs.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ethicaltomas/aitc/internal/config"
	ingestion "github.com/ethicaltomas/aitc/services/ingestion"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ingestion: fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "configs/env/ingestion.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	return ingestion.Run(cfg)
}


