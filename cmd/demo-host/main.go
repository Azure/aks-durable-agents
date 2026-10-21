// Command demo-host is only for the disposable, fake-model kind demo.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/Azure/aks-durable-agents/internal/demohost"
	"github.com/Azure/aks-durable-agents/internal/host"
)

func main() {
	syscall.Umask(0077)
	if len(os.Args) > 1 && os.Args[1] == "health-probe" {
		probe := exec.Command("/production-host", os.Args[1:]...)
		probe.Stdout, probe.Stderr = os.Stdout, os.Stderr
		if err := probe.Run(); err != nil {
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "DEMO ONLY: deterministic local fake model; identity not exercised; never expose this host")
	config, closeProvider, err := demohost.Config(os.Args[1:])
	if err == nil {
		defer closeProvider()
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = host.Run(ctx, config, slog.Default())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "demo host:", err)
		os.Exit(1)
	}
}
