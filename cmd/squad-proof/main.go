//go:build squadproof

// Command squad-proof serves explicitly opted-in local proof fixtures. It is
// never part of a production/default build or an image publication target.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Azure/aks-durable-agents/internal/squadproof"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := squadproof.RunCLI(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
