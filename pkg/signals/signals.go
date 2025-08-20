// Package signals provides a small helper to wire SIGINT/SIGTERM to graceful shutdown.
//
// Setup installs an OS signal handler that listens for SIGINT and SIGTERM.
// When one of those signals is received it will:
//   - log the signal (via standard log package)
//   - close the provided stopCh (if non-nil)
//   - cancel and return a context that will be Done()
//
// The function returns the context which the caller can use to wait for cancellation.
// Closing the provided stopCh is done inside a recover() wrapper to avoid panics
// in case the channel was closed elsewhere.
package signals

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// Setup registers a handler for SIGINT and SIGTERM.
// It returns a context.Context that will be canceled when a signal is received.
// If stopCh is non-nil it will be closed when a signal is received.
func Setup(stopCh chan struct{}) context.Context {
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("signal received: %s - shutting down", sig)

		// Close stopCh if provided. Use recover to avoid panic if it's already closed.
		if stopCh != nil {
			func() {
				defer func() { _ = recover() }()
				close(stopCh)
			}()
		}

		// Cancel the context so callers can observe ctx.Done()
		cancel()
	}()

	return ctx
}
