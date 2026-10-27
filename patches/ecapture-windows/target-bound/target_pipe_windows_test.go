//go:build windows

package main

import (
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestTargetBoundSelfTokenAndGeneration(t *testing.T) {
	pid := uint32(os.Getpid())
	birth, err := enhancedBirth(pid)
	if err != nil {
		t.Fatal("self identity unavailable")
	}
	sd, err := enhancedTargetPipeSecurity(pid, birth)
	if err != nil || sd == nil {
		t.Fatal("self target-bound descriptor unavailable", err)
	}
	text := sd.String()
	if !strings.Contains(text, "S:(ML;;NW;;;LW)") {
		t.Fatal("audit endpoint low-integrity label missing")
	}
	if _, err = enhancedTargetPipeSecurity(pid, birth+1); err == nil {
		t.Fatal("stale target generation accepted")
	}
}

func TestTargetBoundSIDRejectsInvalidRanges(t *testing.T) {
	if _, err := targetSIDFromBuffer(nil, nil); err == nil {
		t.Fatal("nil SID accepted")
	}
	data := make([]byte, 8)
	if _, err := targetSIDFromBuffer(data, (*windows.SID)(unsafe.Pointer(&data[7]))); err == nil {
		t.Fatal("short SID accepted")
	}
	data[1] = 16
	if _, err := targetSIDFromBuffer(data, (*windows.SID)(unsafe.Pointer(&data[0]))); err == nil {
		t.Fatal("excessive subauthority count accepted")
	}
	other := make([]byte, 8)
	if _, err := targetSIDFromBuffer(data, (*windows.SID)(unsafe.Pointer(&other[0]))); err == nil {
		t.Fatal("SID outside token buffer accepted")
	}
}

func TestTargetBoundTokenInformationBound(t *testing.T) {
	if _, err := targetTokenInfo(windows.Token(0), windows.TokenUser); err == nil {
		t.Fatal("invalid token accepted")
	}
	for _, class := range []uint32{windows.TokenUser, windows.TokenRestrictedSids} {
		data, err := targetTokenInfo(windows.GetCurrentProcessToken(), class)
		if err != nil || len(data) == 0 || len(data) > targetTokenInfoLimit {
			t.Fatal("current token could not be queried within the bound", err)
		}
	}
}
