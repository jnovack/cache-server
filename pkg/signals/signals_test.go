package signals

import (
	"syscall"
	"testing"
	"time"
)

// TestSetupSIGTERM ensures SIGTERM triggers stopCh closure and ctx cancellation.
func TestSetupSIGTERM(t *testing.T) {
	stopCh := make(chan struct{})
	ctx := Setup(stopCh)

	// Send SIGTERM after a short delay to allow the goroutine to install the handler.
	time.AfterFunc(50*time.Millisecond, func() {
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	})

	// First, wait on stopCh being closed.
	select {
	case <-stopCh:
		// ok
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for stopCh after SIGTERM")
	}

	// Then, ensure ctx is canceled.
	select {
	case <-ctx.Done():
		// ok
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for ctx.Done() after SIGTERM")
	}
}

// TestSetupSignalHandlerSIGINT ensures SIGINT triggers stopCh closure and ctx cancellation.
func TestSetupSignalHandlerSIGINT(t *testing.T) {
	stopCh := make(chan struct{})
	ctx := Setup(stopCh)

	// Send SIGINT after a short delay.
	time.AfterFunc(50*time.Millisecond, func() {
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	})

	select {
	case <-stopCh:
		// ok
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for stopCh after SIGINT")
	}

	select {
	case <-ctx.Done():
		// ok
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for ctx.Done() after SIGINT")
	}
}
