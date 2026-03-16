package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ethicaltomas/aitc/internal/config"
	controlplane "github.com/ethicaltomas/aitc/services/controlplane"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "controlplane: fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "configs/env/controlplane.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	return controlplane.Run(cfg)
}


