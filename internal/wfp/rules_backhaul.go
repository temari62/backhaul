//go:build windows

package wfp

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Backhaul's additions to the WireGuard rule set.

// lanV4 / lanV6 are local-network destinations: private and link-local
// ranges, multicast and broadcast. Allowing them keeps the router, printers
// and LAN shares reachable — and anything Windows itself does on the LAN.
var (
	lanV4 = []wtFwpV4AddrAndMask{
		{0x0a000000, 0xff000000}, // 10.0.0.0/8
		{0xac100000, 0xfff00000}, // 172.16.0.0/12
		{0xc0a80000, 0xffff0000}, // 192.168.0.0/16
		{0xa9fe0000, 0xffff0000}, // 169.254.0.0/16
		{0xe0000000, 0xf0000000}, // 224.0.0.0/4 multicast
		{0xffffffff, 0xffffffff}, // broadcast
	}
	lanV6 = []wtFwpV6AddrAndMask{
		{[16]uint8{0xfe, 0x80}, 10}, // link-local
		{[16]uint8{0xfc}, 7},        // unique local
		{[16]uint8{0xff}, 8},        // multicast
	}
)

// permitLAN allows traffic to and from the local network on any adapter.
// The tunnel's own subnet is in 10.0.0.0/8 too, which is harmless: it is
// only reachable through the tunnel.
func permitLAN(session uintptr, baseObjects *baseObjects, weight uint8) error {
	var v4 []wtFwpmFilterCondition0
	for i := range lanV4 {
		v4 = append(v4, wtFwpmFilterCondition0{
			fieldKey:       cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType:      cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_V4_ADDR_MASK, value: uintptr(unsafe.Pointer(&lanV4[i]))},
		})
	}
	var v6 []wtFwpmFilterCondition0
	for i := range lanV6 {
		v6 = append(v6, wtFwpmFilterCondition0{
			fieldKey:       cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType:      cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_V6_ADDR_MASK, value: uintptr(unsafe.Pointer(&lanV6[i]))},
		})
	}
	for _, f := range []struct {
		name  string
		layer windows.GUID
		conds []wtFwpmFilterCondition0
	}{
		{"Permit outbound to the local network (IPv4)", cFWPM_LAYER_ALE_AUTH_CONNECT_V4, v4},
		{"Permit inbound from the local network (IPv4)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, v4},
		{"Permit outbound to the local network (IPv6)", cFWPM_LAYER_ALE_AUTH_CONNECT_V6, v6},
		{"Permit inbound from the local network (IPv6)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, v6},
	} {
		if err := addFilter(session, baseObjects, weight, f.name, f.layer, f.conds, cFWP_ACTION_PERMIT); err != nil {
			return err
		}
	}
	return nil
}

// permitService lets a Windows service connect anywhere. Used for the
// Network Location Awareness service, whose connectivity check (NCSI) probes
// the internet on each adapter directly: if a kill switch blocks it, Windows
// decides the real adapter has "No Internet" and may wind its connections
// down — on one user's PC every connection outside the tunnel failed about a
// minute after the kill switch went on. The probes only fetch Microsoft's
// connectivity-test page.
func permitService(session uintptr, baseObjects *baseObjects, weight uint8, service string) error {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+service)
	if err != nil {
		return wrapErr(err)
	}
	access := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: cFWP_ACTRL_MATCH_FILTER,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}
	dacl, err := windows.ACLFromEntries(access, nil)
	if err != nil {
		return wrapErr(err)
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return wrapErr(err)
	}
	if err := sd.SetDACL(dacl, true, false); err != nil {
		return wrapErr(err)
	}
	if sd, err = sd.ToSelfRelative(); err != nil {
		return wrapErr(err)
	}
	blob := wtFwpByteBlob{sd.Length(), (*byte)(unsafe.Pointer(sd))}
	conds := []wtFwpmFilterCondition0{{
		fieldKey:       cFWPM_CONDITION_ALE_USER_ID,
		matchType:      cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{_type: cFWP_SECURITY_DESCRIPTOR_TYPE, value: uintptr(unsafe.Pointer(&blob))},
	}}
	for _, l := range []windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V4, cFWPM_LAYER_ALE_AUTH_CONNECT_V6} {
		if err := addFilter(session, baseObjects, weight, "Permit Windows service "+service, l, conds, cFWP_ACTION_PERMIT); err != nil {
			return err
		}
	}
	return nil
}

func addFilter(session uintptr, baseObjects *baseObjects, weight uint8, name string, layer windows.GUID,
	conds []wtFwpmFilterCondition0, action wtFwpActionType) error {
	displayData, err := createWtFwpmDisplayData0(name, "")
	if err != nil {
		return wrapErr(err)
	}
	filter := wtFwpmFilter0{
		displayData: *displayData,
		providerKey: &baseObjects.provider,
		layerKey:    layer,
		subLayerKey: baseObjects.filters,
		weight:      filterWeight(weight),
		action:      wtFwpmAction0{_type: action},
	}
	if len(conds) > 0 {
		filter.numFilterConditions = uint32(len(conds))
		filter.filterCondition = &conds[0]
	}
	filterID := uint64(0)
	return wrapErr(fwpmFilterAdd0(session, &filter, 0, &filterID))
}
