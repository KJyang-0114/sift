package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/KJyang-0114/sift/internal/cmd"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := cmd.Execute(ctx, version, commit, date, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(cmd.ExitCode(err))
	}
}
