//go:build windows

package transport

import (
	"log/slog"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// setProcAttr is a no-op on Windows; see afterStart.
func setProcAttr(*exec.Cmd) {}

var (
	jobOnce sync.Once
	job     windows.Handle
	jobErr  error
)

// killOnExitJob is a Job Object configured to kill every process in it when
// its last handle closes. backhaul never closes it, so Windows closes it when
// backhaul exits for any reason (clean exit, crash, Task Manager) and takes
// wstunnel down with it — no orphan left holding port 443.
func killOnExitJob() (windows.Handle, error) {
	jobOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			jobErr = err
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
			BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
				LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			},
		}
		if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			windows.CloseHandle(h)
			jobErr = err
			return
		}
		job = h
	})
	return job, jobErr
}

// afterStart ties the child's lifetime to ours.
func afterStart(cmd *exec.Cmd) {
	if err := bindToOurLifetime(cmd.Process.Pid); err != nil {
		slog.Warn("could not tie wstunnel to backhaul's lifetime; it may outlive a crash", "err", err)
	}
}

func bindToOurLifetime(pid int) error {
	j, err := killOnExitJob()
	if err != nil {
		return err
	}
	p, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(p)
	return windows.AssignProcessToJobObject(j, p)
}
