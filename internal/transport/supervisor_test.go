package transport

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"
)

// TestSupervisorHelperProcess is re-executed as a stand-in transport.
func TestSupervisorHelperProcess(t *testing.T) {
	if os.Getenv("BH_SUP_HELPER") != "1" {
		return
	}
	fmt.Println("core: started")
	time.Sleep(300 * time.Millisecond)
	fmt.Println("write tcp: wsasend: An existing connection was forcibly closed by the remote host.")
	time.Sleep(time.Minute)
	os.Exit(0)
}

func TestSupervisorRestartsOnCutMessage(t *testing.T) {
	os.Setenv("BH_SUP_HELPER", "1")
	defer os.Unsetenv("BH_SUP_HELPER")
	s := NewSupervisor(ProcSpec{Kind: "fake", Binary: os.Args[0], Args: []string{"-test.run=^TestSupervisorHelperProcess$"},
		ReadyRE: regexp.MustCompile(`core: started`), RestartOn: xrayCutRE,
		ReadyTimeout: 10 * time.Second, BackoffMin: 50 * time.Millisecond, BackoffMax: 100 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	deadline := time.Now().Add(10 * time.Second)
	for s.Status().Restarts == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the cut message did not restart the process: %+v", s.Status())
		}
		time.Sleep(50 * time.Millisecond)
	}
}
