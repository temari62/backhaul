//go:build windows

package tray

import (
	"testing"
	"unsafe"
)

// The struct must match SHELLEXECUTEINFOW exactly or ShellExecuteExW fails.
func TestShellExecuteInfoABI(t *testing.T) {
	want := map[uintptr]uintptr{8: 112, 4: 60}[unsafe.Sizeof(uintptr(0))]
	if sizeofShellExecuteInfo != want {
		t.Fatalf("sizeof(SHELLEXECUTEINFOW) = %d, want %d", sizeofShellExecuteInfo, want)
	}
	if off := unsafe.Offsetof(shellExecuteInfo{}.hProcess); off != want-unsafe.Sizeof(uintptr(0)) {
		t.Fatalf("hProcess at %d", off)
	}
}
