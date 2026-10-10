//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 *
 * Adapted for Backhaul from wireguard-windows tunnel/firewall (v0.5.3).
 */

// Package wfp is Backhaul's Windows kill switch: filters in the Windows
// Filtering Platform that block all traffic except through the tunnel
// adapter, from allowed programs (Backhaul itself, Xray), on loopback, and
// for DHCP/IPv6 neighbour discovery.
//
// Unlike Windows Firewall rules, the filters live in a *dynamic* WFP
// session: Windows removes them by itself the moment Backhaul exits or
// crashes, so the network can never be left blocked. They also don't depend
// on Windows Firewall profiles or its rule compiler (rules created through
// Windows Firewall began blocking the exit node about a minute after being
// installed on a user's PC).
package wfp

import (
	"errors"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpObjectInstaller func(uintptr) error

// Fundamental Backhaul-specific WFP objects.
type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

var (
	mu         sync.Mutex
	wfpSession uintptr
)

func createWfpSession() (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("Backhaul", "Backhaul kill switch (dynamic session)")
	if err != nil {
		return 0, wrapErr(err)
	}

	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,
		flags:                cFWPM_SESSION_FLAG_DYNAMIC,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}

	sessionHandle := uintptr(0)

	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}

	return sessionHandle, nil
}

func registerBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{}
	var err error
	bo.provider, err = windows.GenerateGUID()
	if err != nil {
		return nil, wrapErr(err)
	}
	bo.filters, err = windows.GenerateGUID()
	if err != nil {
		return nil, wrapErr(err)
	}

	{
		displayData, err := createWtFwpmDisplayData0("Backhaul", "Backhaul kill switch provider")
		if err != nil {
			return nil, wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: bo.provider,
			displayData: *displayData,
		}
		err = fwpmProviderAdd0(session, &provider, 0)
		if err != nil {
			return nil, wrapErr(err)
		}
	}

	{
		displayData, err := createWtFwpmDisplayData0("Backhaul filters", "Permissive and blocking filters")
		if err != nil {
			return nil, wrapErr(err)
		}
		sublayer := wtFwpmSublayer0{
			subLayerKey: bo.filters,
			displayData: *displayData,
			providerKey: &bo.provider,
			weight:      ^uint16(0),
		}
		err = fwpmSubLayerAdd0(session, &sublayer, 0)
		if err != nil {
			return nil, wrapErr(err)
		}
	}

	return bo, nil
}

// Options configures the kill switch.
type Options struct {
	// TunLUID is the tunnel adapter's LUID; all its traffic is allowed.
	TunLUID uint64
	// PermitApps are executables allowed to connect anywhere: Backhaul
	// itself (its TLS proxy carries the tunnel) and Xray for REALITY.
	PermitApps []string
	// PermitServices are Windows services (by name) allowed to connect
	// anywhere, e.g. "NlaSvc" for Windows' internet-connectivity check.
	// Services that don't exist are skipped.
	PermitServices []string
	// AllowLAN permits traffic with the local network.
	AllowLAN bool
	// ScopeApps, for tests only, limits the block to these executables so
	// the rest of the machine is unaffected.
	ScopeApps []string
}

// Enable installs the kill switch. It replaces one installed earlier by this
// process.
func Enable(o Options) error {
	mu.Lock()
	defer mu.Unlock()
	if wfpSession != 0 {
		fwpmEngineClose0(wfpSession)
		wfpSession = 0
	}
	if len(o.PermitApps) == 0 {
		return errors.New("kill switch: no program is allowed to reach the exit node")
	}

	var ids []*wtFwpByteBlob
	defer func() {
		for i := range ids {
			fwpmFreeMemory0(unsafe.Pointer(&ids[i]))
		}
	}()
	appID := func(path string) (*wtFwpByteBlob, error) {
		id, err := getAppID(path)
		if err == nil {
			ids = append(ids, id)
		}
		return id, err
	}

	var scope []wtFwpmFilterCondition0
	for _, p := range o.ScopeApps {
		id, err := appID(p)
		if err != nil {
			return err
		}
		scope = append(scope, wtFwpmFilterCondition0{
			fieldKey:       cFWPM_CONDITION_ALE_APP_ID,
			matchType:      cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_BYTE_BLOB_TYPE, value: uintptr(unsafe.Pointer(id))},
		})
	}

	session, err := createWfpSession()
	if err != nil {
		return wrapErr(err)
	}

	objectInstaller := func(session uintptr) error {
		baseObjects, err := registerBaseObjects(session)
		if err != nil {
			return wrapErr(err)
		}
		for _, p := range o.PermitApps {
			id, err := appID(p)
			if err != nil {
				return err
			}
			if err := permitApp(session, baseObjects, 15, id); err != nil {
				return wrapErr(err)
			}
		}
		for _, s := range o.PermitServices {
			_ = permitService(session, baseObjects, 14, s) // best effort
		}
		if o.AllowLAN {
			if err := permitLAN(session, baseObjects, 13); err != nil {
				return wrapErr(err)
			}
		}
		if err := permitLoopback(session, baseObjects, 13); err != nil {
			return wrapErr(err)
		}
		if o.TunLUID != 0 {
			if err := permitTunInterface(session, baseObjects, 12, o.TunLUID); err != nil {
				return wrapErr(err)
			}
		}
		if err := permitDHCPIPv4(session, baseObjects, 12); err != nil {
			return wrapErr(err)
		}
		if err := permitDHCPIPv6(session, baseObjects, 12); err != nil {
			return wrapErr(err)
		}
		if err := permitNdp(session, baseObjects, 12); err != nil {
			return wrapErr(err)
		}
		return blockAll(session, baseObjects, 0, scope)
	}

	if err := runTransaction(session, objectInstaller); err != nil {
		fwpmEngineClose0(session)
		return wrapErr(err)
	}
	wfpSession = session
	return nil
}

// Disable removes the kill switch (Windows also does so when the process
// exits).
func Disable() {
	mu.Lock()
	defer mu.Unlock()
	if wfpSession != 0 {
		fwpmEngineClose0(wfpSession)
		wfpSession = 0
	}
}

// Enabled reports whether the kill switch is installed.
func Enabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return wfpSession != 0
}
