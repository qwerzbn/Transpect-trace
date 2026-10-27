//go:build windows

// An opt-in audit endpoint for one already verified process lifetime. The
// target token and sandbox are unchanged. runEnhanced still verifies pipe peer
// PID and creation time before exchanging configuration or accepting frames.
package main

import (
	"errors"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const targetTokenInfoLimit = 65536
const targetRestrictedSIDLimit = 256

func targetTokenInfo(token windows.Token, class uint32) ([]byte, error) {
	var needed uint32
	err := windows.GetTokenInformation(token, class, nil, 0, &needed)
	if err != windows.ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > targetTokenInfoLimit {
		return nil, errors.New("target_token_information_unavailable")
	}
	data := make([]byte, needed)
	if windows.GetTokenInformation(token, class, &data[0], needed, &needed) != nil || needed == 0 || int(needed) > len(data) {
		return nil, errors.New("target_token_information_changed")
	}
	return data[:needed], nil
}

func targetSIDFromBuffer(data []byte, sid *windows.SID) (string, error) {
	if len(data) == 0 || sid == nil {
		return "", errors.New("target_token_sid_invalid")
	}
	start, value := uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(sid))
	end := start + uintptr(len(data))
	if value < start || value > end || end-value < 8 {
		return "", errors.New("target_token_sid_outside_buffer")
	}
	count := *(*byte)(unsafe.Pointer(value + 1))
	if count > 15 || uintptr(8+4*int(count)) > end-value || !sid.IsValid() {
		return "", errors.New("target_token_sid_invalid")
	}
	text := sid.String()
	runtime.KeepAlive(data)
	if text == "" || !strings.HasPrefix(text, "S-") {
		return "", errors.New("target_token_sid_invalid")
	}
	return text, nil
}

func targetProcessBirth(process windows.Handle) (uint64, error) {
	var birth, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(process, &birth, &exit, &kernel, &user) != nil {
		return 0, errors.New("target_times_unavailable")
	}
	return uint64(birth.HighDateTime)<<32 | uint64(birth.LowDateTime), nil
}

func enhancedTargetPipeSecurity(pid uint32, expected uint64) (*windows.SECURITY_DESCRIPTOR, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, errors.New("target_token_process_unavailable")
	}
	defer windows.CloseHandle(process)
	birth, err := targetProcessBirth(process)
	if err != nil || birth != expected {
		return nil, errors.New("target_generation_mismatch")
	}
	var token windows.Token
	if windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token) != nil {
		return nil, errors.New("target_token_unavailable")
	}
	defer token.Close()
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current.User.Sid == nil || !current.User.Sid.IsValid() {
		return nil, errors.New("token_identity_unavailable")
	}
	userData, err := targetTokenInfo(token, windows.TokenUser)
	if err != nil || len(userData) < int(unsafe.Sizeof(windows.Tokenuser{})) {
		return nil, errors.New("target_token_user_unavailable")
	}
	user := (*windows.Tokenuser)(unsafe.Pointer(&userData[0]))
	targetUser, err := targetSIDFromBuffer(userData, user.User.Sid)
	if err != nil {
		return nil, err
	}
	groupsData, err := targetTokenInfo(token, windows.TokenRestrictedSids)
	if err != nil || len(groupsData) < 4 {
		return nil, errors.New("target_restricted_sids_unavailable")
	}
	count := *(*uint32)(unsafe.Pointer(&groupsData[0]))
	var layout windows.Tokengroups
	offset := unsafe.Offsetof(layout.Groups)
	entrySize := unsafe.Sizeof(windows.SIDAndAttributes{})
	if count > targetRestrictedSIDLimit || (count > 0 && offset+uintptr(count)*entrySize > uintptr(len(groupsData))) {
		return nil, errors.New("target_restricted_sids_limit")
	}
	// GR/GW is needed for the existing duplex audit/configuration handshake.
	// Only SIDs read from this exact target token are added; there are no
	// unconditional Everyone, Users, Administrators or app-container ACEs.
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;" + current.User.Sid.String() + ")"
	seen := map[string]bool{current.User.Sid.String(): true, "S-1-5-18": true}
	appendSID := func(value string) {
		if !seen[value] {
			seen[value] = true
			sddl += "(A;;GRGW;;;" + value + ")"
		}
	}
	appendSID(targetUser)
	for i := uint32(0); i < count; i++ {
		entry := (*windows.SIDAndAttributes)(unsafe.Pointer(uintptr(unsafe.Pointer(&groupsData[0])) + offset + uintptr(i)*entrySize))
		value, err := targetSIDFromBuffer(groupsData, entry.Sid)
		if err != nil {
			return nil, err
		}
		appendSID(value)
	}
	// Mandatory integrity applies only to this local audit pipe. Peer identity
	// remains checked by runEnhanced; it is not an authorization bypass.
	sddl += "S:(ML;;NW;;;LW)"
	birth, err = targetProcessBirth(process)
	observed, observedErr := enhancedBirth(pid)
	if err != nil || observedErr != nil || birth != expected || observed != expected {
		return nil, errors.New("target_generation_mismatch")
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, errors.New("pipe_security_unavailable")
	}
	return sd, nil
}
