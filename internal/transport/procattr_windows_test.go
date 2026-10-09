//go:build windows

package transport

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestJobHelperProcess is not a real test: it is re-executed by
// TestChildDiesWhenParentIsKilled as the "parent" (stand-in for backhaul)
// or the "child" (stand-in for wstunnel).
func TestJobHelperProcess(t *testing.T) {
	switch os.Getenv("BH_JOB_ROLE") {
	case "child":
		time.Sleep(2 * time.Minute)
		os.Exit(0)
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestJobHelperProcess$")
		child.Env = append(os.Environ(), "BH_JOB_ROLE=child")
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		afterStart(child) // what runOnce does for wstunnel
		os.Stdout.WriteString(strconv.Itoa(child.Process.Pid) + "\n")
		time.Sleep(2 * time.Minute)
		os.Exit(0)
	}
}

func alive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	ev, _ := windows.WaitForSingleObject(h, 0)
	return ev == uint32(windows.WAIT_TIMEOUT)
}

// A crashed or force-killed backhaul must not leave wstunnel running.
func TestChildDiesWhenParentIsKilled(t *testing.T) {
	parent := exec.Command(os.Args[0], "-test.run=^TestJobHelperProcess$")
	parent.Env = append(os.Environ(), "BH_JOB_ROLE=parent")
	out, err := parent.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		parent.Process.Kill()
		t.Fatalf("parent did not report its child: %v", err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(line))
	if !alive(pid) {
		t.Fatal("child not running before the parent is killed")
	}

	parent.Process.Kill() // TerminateProcess: like a crash or Task Manager "End task"
	parent.Wait()

	deadline := time.Now().Add(10 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/F").Run()
			t.Fatal("child (wstunnel stand-in) outlived its killed parent")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
