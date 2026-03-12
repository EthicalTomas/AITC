// cmd/pipeline is the pipeline service binary.
// It loads configuration and delegates to services/pipeline.Run().
package main

import (
"flag"
"fmt"
"os"

"github.com/ethicaltomas/aitc/internal/config"
pipeline "github.com/ethicaltomas/aitc/services/pipeline"
)

func main() {
cfgPath := flag.String("config", "configs/env/pipeline.yaml", "path to YAML config file")
flag.Parse()

cfg, err := config.LoadConfig(*cfgPath)
if err != nil {
fmt.Fprintf(os.Stderr, "pipeline: failed to load config: %v\n", err)
os.Exit(1)
}

if err := pipeline.Run(cfg); err != nil {
fmt.Fprintf(os.Stderr, "pipeline: fatal error: %v\n", err)
os.Exit(1)
}
}
