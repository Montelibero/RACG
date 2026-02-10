package main

import (
	"os"

	"github.com/itolstov/racg/internal/cli"
)

func main() {
	root := cli.NewRoot(os.Stdout, os.Stderr)
	os.Exit(root.Run(os.Args[1:]))
}
