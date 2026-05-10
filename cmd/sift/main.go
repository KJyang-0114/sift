package main

import (
	"fmt"
	"os"

	"github.com/KJyang-0114/sift/internal/cmd"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	root := cmd.NewRootCmd(version, commit, date)
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
