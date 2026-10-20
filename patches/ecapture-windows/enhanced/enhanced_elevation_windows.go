//go:build windows

package main

// One-shot, same-user elevation relay. No service, group changes, TCP listener,
// plaintext files, or privilege changes in the observed application.
import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var enhancedInput io.Reader = os.Stdin
var enhancedOutput io.Writer = os.Stdout
var enhancedDiagnostic io.Writer = os.Stderr

type relayWriter struct {
	relay *elevationRelay
	kind  byte
}
type elevationRelay struct {
	file  *os.File
	mu    sync.Mutex
	held  []windows.Handle
	files []*os.File
}

func (w relayWriter) Write(b []byte) (int, error) {
	if len(b) > enhancedHeader+65536 {
		return 0, errors.New("relay_frame_limit")
	}
	w.relay.mu.Lock()
	defer w.relay.mu.Unlock()
	if err := w.relay.file.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return 0, err
	}
	header := make([]byte, 5)
	header[0] = w.kind
	binary.LittleEndian.PutUint32(header[1:], uint32(len(b)))
	if _, err := w.relay.file.Write(header); err != nil {
		return 0, err
	}
	return w.relay.file.Write(b)
}
func (r *elevationRelay) close(code uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], code)
	_, _ = (relayWriter{r, 'X'}).Write(b[:])
	r.file.Close()
	for _, f := range r.files {
		f.Close()
	}
	for _, h := range r.held {
		windows.CloseHandle(h)
	}
}

func sameUserProcess(pid uint32, expected uint64) (windows.Handle, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return 0, errors.New("relay_process_unavailable")
	}
	fail := func() (windows.Handle, error) {
		windows.CloseHandle(h)
		return 0, errors.New("relay_identity_mismatch")
	}
	var a, b, c, d windows.Filetime
	if windows.GetProcessTimes(h, &a, &b, &c, &d) != nil || uint64(a.HighDateTime)<<32|uint64(a.LowDateTime) != expected {
		return fail()
	}
	if state, _ := windows.WaitForSingleObject(h, 0); state != uint32(windows.WAIT_TIMEOUT) {
		return fail()
	}
	var token windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
		return fail()
	}
	defer token.Close()
	theirs, e1 := token.GetTokenUser()
	ours, e2 := windows.GetCurrentProcessToken().GetTokenUser()
	if e1 != nil || e2 != nil || !theirs.User.Sid.Equals(ours.User.Sid) {
		return fail()
	}
	return h, nil
}

func lockedDigest(path, want string) (*os.File, error) {
	if len(want) != 64 {
		return nil, errors.New("relay_hash_invalid")
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("relay_path_invalid")
	}
	// Deny replacement/write while the privileged operation uses this file.
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New("relay_file_unavailable")
	}
	f := os.NewFile(uintptr(h), path)
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil || hex.EncodeToString(hash.Sum(nil)) != want {
		f.Close()
		return nil, errors.New("relay_hash_mismatch")
	}
	return f, nil
}

// Arguments contain only local identities and hashes; never request contents.
func openElevationRelay(args []string) (r *elevationRelay, err error) {
	if len(args) != 8 || !strings.HasPrefix(args[0], `\\.\pipe\ttrace-ecapture-uac-`) || len(args[0]) != len(`\\.\pipe\ttrace-ecapture-uac-`)+32 {
		return nil, errors.New("relay_arguments_invalid")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, errors.New("requires administrator privileges")
	}
	parent, e1 := strconv.ParseUint(args[1], 10, 32)
	parentBirth, e2 := strconv.ParseUint(args[2], 10, 64)
	target, e3 := strconv.ParseUint(args[3], 10, 32)
	targetBirth, e4 := strconv.ParseUint(args[4], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || parent == 0 || target == 0 {
		return nil, errors.New("relay_arguments_invalid")
	}
	r = &elevationRelay{}
	cleanup := r
	defer func() {
		if err != nil {
			for _, h := range cleanup.held {
				windows.CloseHandle(h)
			}
			for _, f := range cleanup.files {
				f.Close()
			}
			if cleanup.file != nil {
				cleanup.file.Close()
			}
		}
	}()
	for _, identity := range [][2]uint64{{parent, parentBirth}, {target, targetBirth}} {
		h, e := sameUserProcess(uint32(identity[0]), identity[1])
		if e != nil {
			return nil, e
		}
		r.held = append(r.held, h)
	}
	image := make([]uint16, 32768)
	n := uint32(len(image))
	if windows.QueryFullProcessImageName(r.held[1], 0, &image[0], &n) != nil {
		return nil, errors.New("relay_target_image_unavailable")
	}
	exe, _ := os.Executable()
	for _, item := range [][2]string{{windows.UTF16ToString(image[:n]), args[5]}, {filepath.Join(filepath.Dir(exe), "schannel_hook.dll"), args[6]}, {exe, args[7]}} {
		f, e := lockedDigest(item[0], item[1])
		if e != nil {
			return nil, e
		}
		r.files = append(r.files, f)
	}
	name, _ := windows.UTF16PtrFromString(args[0])
	var pipe windows.Handle
	deadline := time.Now().Add(10 * time.Second)
	for {
		// Overlapped I/O allows the pending STOP read and data writes to proceed
		// independently. A synchronous Windows handle serializes them.
		pipe, err = windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, errors.New("relay_connect_failed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.file = os.NewFile(uintptr(pipe), "ecapture-elevation-relay")
	var peer uint32
	ok, _, _ := enhancedKernel.NewProc("GetNamedPipeServerProcessId").Call(uintptr(pipe), uintptr(unsafe.Pointer(&peer)))
	if ok == 0 || peer != uint32(parent) {
		return nil, errors.New("relay_server_mismatch")
	}
	os.Setenv("TTRACE_ECAPTURE_PID", fmt.Sprint(target))
	os.Setenv("TTRACE_ECAPTURE_BIRTH", fmt.Sprint(targetBirth))
	return r, nil
}
