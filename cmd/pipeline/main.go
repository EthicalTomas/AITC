package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ethicaltomas/aitc/internal/config"
	pipeline "github.com/ethicaltomas/aitc/services/pipeline"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "pipeline: fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "configs/env/pipeline.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	return pipeline.Run(cfg)
}

