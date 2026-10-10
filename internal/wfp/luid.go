//go:build windows

package wfp

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procConvertInterfaceIndexToLuid = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceIndexToLuid")

// InterfaceLUID returns the LUID of the network adapter called name.
func InterfaceLUID(name string) (uint64, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("find adapter %q: %w", name, err)
	}
	var luid uint64
	if r, _, _ := procConvertInterfaceIndexToLuid.Call(uintptr(ifc.Index), uintptr(unsafe.Pointer(&luid))); r != 0 {
		return 0, fmt.Errorf("LUID of adapter %q: %w", name, syscall.Errno(r))
	}
	return luid, nil
}
