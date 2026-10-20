//go:build windows

// Explicit enhanced entrypoint. Stock CLI is untouched unless the private
// launcher selects this variant. No plaintext passes through console loggers.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unsafe"

	"github.com/gojue/ecapture/pkg/util/etw"
	"github.com/gojue/ecapture/pkg/util/hook"
	"golang.org/x/sys/windows"
)

const enhancedHeader = 112

var enhancedKernel = windows.NewLazySystemDLL("kernel32.dll")

func init() {
	var relay *elevationRelay
	if len(os.Args) > 1 && os.Args[1] == "--ttrace-elevated-ECW2" {
		var err error
		relay, err = openElevationRelay(os.Args[2:])
		if err != nil {
			os.Exit(2)
		}
		enhancedInput = relay.file
		enhancedOutput = relayWriter{relay, 'D'}
		enhancedDiagnostic = relayWriter{relay, 'E'}
	} else if os.Getenv("TTRACE_ECAPTURE_ENHANCED") != "ECW2" {
		return
	}
	if err := runEnhanced(); err != nil {
		// Fixed diagnostics only; never include buffers, request URLs or secrets.
		fmt.Fprintln(enhancedDiagnostic, "enhanced_capture_unavailable:", err.Error())
		if relay != nil {
			relay.close(1)
		}
		os.Exit(1)
	}
	if relay != nil {
		relay.close(0)
	}
	os.Exit(0)
}

func enhancedBirth(pid uint32) (uint64, error) {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, errors.New("target_identity_unavailable")
	}
	defer windows.CloseHandle(p)
	var birth, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(p, &birth, &exit, &kernel, &user) != nil {
		return 0, errors.New("target_times_unavailable")
	}
	return uint64(birth.HighDateTime)<<32 | uint64(birth.LowDateTime), nil
}

func runEnhanced() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("requires administrator privileges")
	}
	pid64, err := strconv.ParseUint(os.Getenv("TTRACE_ECAPTURE_PID"), 10, 32)
	if err != nil || pid64 == 0 {
		return errors.New("invalid_target_pid")
	}
	pid := uint32(pid64)
	birth, err := enhancedBirth(pid)
	if err != nil {
		return err
	}
	expected, err := strconv.ParseUint(os.Getenv("TTRACE_ECAPTURE_BIRTH"), 10, 64)
	if err != nil || expected != birth {
		return errors.New("target_generation_mismatch")
	}
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return errors.New("token_identity_unavailable")
	}
	// An elevated collector may observe its same-user medium-integrity child.
	// Keep the user/SYSTEM DACL and explicitly permit medium integrity writes.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;" + tokenUser.User.Sid.String() + ")S:(ML;;NW;;;ME)")
	if err != nil {
		return errors.New("pipe_security_unavailable")
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\pipe\ecapture-enhanced-%d-%d`, pid, birth))
	pipe, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_NOWAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, 65536, 65536, 1000, &sa)
	if err != nil {
		return errors.New("pipe_create_failed")
	}
	defer windows.CloseHandle(pipe)
	session, err := etw.NewSession(etw.SessionConfig{SessionName: fmt.Sprintf("eCapture-enhanced-%d-%d", pid, time.Now().UnixNano()),
		Providers: []etw.GUID{etw.SchannelProvider}, Callback: func(_ *etw.EventRecord) {}})
	if err != nil {
		return errors.New("etw_initialize_failed")
	}
	if session.Start() != nil {
		return errors.New("etw_start_failed")
	}
	fmt.Fprintln(enhancedDiagnostic, "ecapture_etw_session_started")
	defer session.Stop()
	exe, _ := os.Executable()
	if hook.InjectDLL(pid, filepath.Join(filepath.Dir(exe), "schannel_hook.dll")) != nil {
		return errors.New("injection_failed")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		err = windows.ConnectNamedPipe(pipe, nil)
		if err == nil || err == windows.ERROR_PIPE_CONNECTED {
			break
		}
		if err != windows.ERROR_PIPE_LISTENING || time.Now().After(deadline) {
			return errors.New("pipe_connect_failed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	var peer uint32
	if windows.GetNamedPipeClientProcessId(pipe, &peer) != nil || peer != pid {
		return errors.New("pipe_peer_mismatch")
	}
	current, err := enhancedBirth(peer)
	if err != nil || current != birth {
		return errors.New("process_generation_mismatch")
	}
	config := make([]byte, enhancedHeader)
	copy(config, "ECW2")
	binary.LittleEndian.PutUint32(config[8:12], pid)
	binary.LittleEndian.PutUint32(config[16:20], 5)
	binary.LittleEndian.PutUint64(config[32:40], birth)
	if _, err = rand.Read(config[40:56]); err != nil {
		return errors.New("session_random_failed")
	}
	var sent uint32
	if windows.WriteFile(pipe, config, &sent, nil) != nil || sent != enhancedHeader {
		return errors.New("configuration_write_failed")
	}
	stop := make(chan struct{})
	go func() { var b [1]byte; _, _ = enhancedInput.Read(b[:]); close(stop) }()
	stopping := false
	ready := false
	buffer := make([]byte, 0, enhancedHeader+65536)
	for {
		if !stopping {
			select {
			case <-stop:
				if windows.WriteFile(pipe, []byte("STOP"), &sent, nil) != nil || sent != 4 {
					return errors.New("stop_write_failed")
				}
				stopping = true
				deadline = time.Now().Add(5 * time.Second)
			default:
			}
		}
		if (!ready || stopping) && time.Now().After(deadline) {
			return errors.New("capture_handshake_or_stop_timeout")
		}
		var available uint32
		r, _, _ := enhancedKernel.NewProc("PeekNamedPipe").Call(uintptr(pipe), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
		if r == 0 {
			return errors.New("capture_pipe_disconnected")
		}
		if available == 0 {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		n := available
		if n > 65536 {
			n = 65536
		}
		data := make([]byte, n)
		var got uint32
		if windows.ReadFile(pipe, data, &got, nil) != nil || got == 0 {
			return errors.New("capture_read_failed")
		}
		buffer = append(buffer, data[:got]...)
		for len(buffer) >= enhancedHeader {
			h := buffer[:enhancedHeader]
			length := binary.LittleEndian.Uint32(h[4:8])
			kind := binary.LittleEndian.Uint32(h[16:20])
			if string(h[:4]) != "ECW2" || length > 65536 || binary.LittleEndian.Uint32(h[8:12]) != pid ||
				binary.LittleEndian.Uint64(h[32:40]) != birth || string(h[40:56]) != string(config[40:56]) {
				return errors.New("invalid_capture_frame")
			}
			if len(buffer) < enhancedHeader+int(length) {
				break
			}
			frame := buffer[:enhancedHeader+int(length)]
			if _, err = io.Copy(enhancedOutput, newEnhancedReader(frame)); err != nil {
				return errors.New("structured_output_failed")
			}
			if kind == 1 {
				ready = true
			}
			if kind == 3 {
				if !stopping {
					return errors.New("unexpected_terminal_health")
				}
				return nil
			}
			copy(buffer, buffer[len(frame):])
			buffer = buffer[:len(buffer)-len(frame)]
		}
		if len(buffer) > enhancedHeader+65536 {
			return errors.New("capture_buffer_limit")
		}
	}
}

// A reader avoids any conversion of binary application data into log strings.
type enhancedReader struct{ data []byte }

func newEnhancedReader(data []byte) *enhancedReader { return &enhancedReader{data: data} }
func (r *enhancedReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
