package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ReBPF/internal/probe"
)

func signalHandler(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nCaught SIGINT... Exiting")
		cancel()
	}()
}

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	signalHandler(cancel)

	if err := probe.Run(ctx); err != nil {
		log.Fatalf("Failed running the probe: %v", err)
	}
}