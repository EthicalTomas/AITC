package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ethicaltomas/aitc/internal/config"
	api "github.com/ethicaltomas/aitc/services/api"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "api: fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "configs/env/api.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.LoadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	return api.Run(cfg)
}

