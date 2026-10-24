// Command owner-client operates an authenticated Sessions host through a private TLS forward.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Azure/aks-durable-agents/internal/ownercli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := ownercli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, ownercli.DeviceCredential); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
