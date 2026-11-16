//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Injected at build time; mirrors the core library provenance.
var (
	revision    = "unknown"
	sourceState = "unknown"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		report, err := json.Marshal(map[string]any{
			"protocol":       helperProtocol,
			"revision":       revision,
			"source_state":   sourceState,
			"identity_ready": true,
		})
		if err != nil {
			os.Exit(1)
		}
		fmt.Println(string(report))
		return
	}
	if len(os.Args) != 5 || os.Args[1] != "--connect" {
		fmt.Fprintln(os.Stderr,
			"usage: justconnect-network-helper --version | --connect <abstract-socket> <pid> <uid>")
		os.Exit(2)
	}
	if err := run(os.Args[2], os.Args[3], os.Args[4]); err != nil {
		fmt.Fprintln(os.Stderr, "justconnect-network-helper:", err)
		os.Exit(1)
	}
}

// run connects back to the authorized application, serves its control
// channel, and withdraws everything it owns before exiting — whether the
// application disconnects, the frame protocol breaks, or a signal arrives.
func run(socketName, pidArg, uidArg string) error {
	if unix.Geteuid() != 0 {
		return errors.New("helper must run as root; pkexec did not elevate it")
	}
	pid, err := strconv.Atoi(pidArg)
	if err != nil || pid <= 0 {
		return fmt.Errorf("invalid application pid %q", pidArg)
	}
	uid, err := strconv.Atoi(uidArg)
	if err != nil || uid < 0 {
		return fmt.Errorf("invalid application uid %q", uidArg)
	}

	if err := prepareStateDir(); err != nil {
		return err
	}
	lock, err := acquireOwnership(uid)
	if err != nil {
		return err
	}
	defer lock.Close()

	// A previous helper may have died without restoring; clean its record
	// before serving so this instance starts from a clean slate.
	if state, err := loadState(uid); err != nil {
		fmt.Fprintf(os.Stderr, "justconnect-network-helper: read leftover state: %v\n", err)
	} else if state != nil {
		if err := withdrawRecordedState(state); err != nil {
			fmt.Fprintf(os.Stderr, "justconnect-network-helper: leftover restore: %v\n", err)
		}
		if err := clearState(uid); err != nil {
			fmt.Fprintf(os.Stderr, "justconnect-network-helper: clear leftover state: %v\n", err)
		}
	}

	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create control socket: %w", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: socketName}); err != nil {
		unix.Close(fd)
		return fmt.Errorf("connect to the application socket: %w", err)
	}
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		unix.Close(fd)
		return fmt.Errorf("inspect the socket peer: %w", err)
	}
	if int(cred.Uid) != uid || int(cred.Pid) != pid {
		unix.Close(fd)
		return fmt.Errorf("socket peer uid=%d pid=%d does not match the authorized identity uid=%d pid=%d",
			cred.Uid, cred.Pid, uid, pid)
	}
	// Nonblocking before os.NewFile registers the socket with the runtime
	// poller: reads block through the poller while read deadlines stay
	// available as the signal-driven shutdown path.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return fmt.Errorf("set the control socket nonblocking: %w", err)
	}

	file := os.NewFile(uintptr(fd), "justconnect-helper-control")
	if file == nil {
		unix.Close(fd)
		return errors.New("wrap the control socket")
	}

	session := &helperSession{uid: uid, pid: pid}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, unix.SIGTERM, unix.SIGINT, unix.SIGHUP)
	go func() {
		<-stop
		// Break a pending read so the shutdown path runs even if the
		// application vanished without closing the socket.
		_ = file.SetReadDeadline(time.Now())
	}()

	err = serve(file, fd, session)
	file.Close()
	// Whatever the exit reason, withdraw everything owned by this session.
	if restoreErr := session.restore(); restoreErr != nil {
		fmt.Fprintf(os.Stderr, "justconnect-network-helper: restore: %v\n", restoreErr)
		if err == nil {
			err = restoreErr
		}
	}
	return err
}

// helperSession owns at most one capture for the connected application.
type helperSession struct {
	uid   int
	pid   int
	state *ownedState
	dev   *tunDevice
}

// serve reads length-prefixed JSON requests and answers each one. It returns
// nil on clean EOF or close.
func serve(file *os.File, connFD int, session *helperSession) error {
	for {
		header := make([]byte, 4)
		if err := readFull(file, header); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) ||
				errors.Is(err, syscall.EINTR) || errors.Is(err, os.ErrDeadlineExceeded) {
				return nil
			}
			return fmt.Errorf("read request header: %w", err)
		}
		length := int(binary.BigEndian.Uint32(header))
		if length == 0 || length > maxRequestBytes {
			return fmt.Errorf("request frame of %d bytes is outside the protocol bound", length)
		}
		payload := make([]byte, length)
		if err := readFull(file, payload); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) ||
				errors.Is(err, os.ErrDeadlineExceeded) {
				return nil
			}
			return fmt.Errorf("read request body: %w", err)
		}

		request, err := parseRequest(payload)
		if err != nil {
			// Answer the best envelope we can reconstruct, then keep serving
			// so the application sees the precise failure.
			if replyErr := sendReply(connFD, malformedReply(payload, err), -1); replyErr != nil {
				return nil
			}
			continue
		}

		reply, attachFD, closeAfter := session.dispatch(request)
		if err := sendReply(connFD, reply, attachFD); err != nil {
			return nil // Application gone; restore runs in the caller.
		}
		if closeAfter {
			return nil
		}
	}
}

// dispatch executes one request; the fd return carries the TUN descriptor
// with the apply reply, and closeAfter ends the session after the reply.
func (s *helperSession) dispatch(request *request) (reply *response, attachFD int, closeAfter bool) {
	attachFD = -1
	switch request.Operation {
	case opProbe:
		mode, err := detectDNSMode()
		reply = request.reply(statusOK, "", nil)
		if err != nil {
			reply.Detail = err.Error()
		}
		reply.DNSMode = mode
	case opApply:
		device, fd, err := s.apply(request)
		if err != nil {
			reply = request.reply(statusFailed, err.Error(), nil)
			break
		}
		reply = request.reply(statusOK, "", device)
		if s.state != nil && s.state.DNS != nil {
			reply.DNSMode = s.state.DNS.Mode
		}
		attachFD = fd
	case opExtend:
		if err := s.extend(request); err != nil {
			reply = request.reply(statusFailed, err.Error(), nil)
			break
		}
		reply = request.reply(statusOK, "", nil)
	case opRoutes:
		if err := s.reconcile(request); err != nil {
			reply = request.reply(statusFailed, err.Error(), nil)
			break
		}
		reply = request.reply(statusOK, "", nil)
	case opRestore, opCleanup:
		if err := s.restore(); err != nil {
			reply = request.reply(statusFailed, err.Error(), nil)
			break
		}
		reply = request.reply(statusOK, "", nil)
	case opClose:
		reply = request.reply(statusOK, "", nil)
		closeAfter = true
	default:
		reply = request.reply(statusFailed, "unknown operation", nil)
	}
	return reply, attachFD, closeAfter
}

// apply creates and configures the capture: TUN device, point-to-point pair,
// write-ahead ownership record, DNS, and the campus routes.
func (s *helperSession) apply(request *request) (*deviceInfo, int, error) {
	if s.state != nil || s.dev != nil {
		return nil, -1, errors.New("a capture is already active; restore it before applying again")
	}
	config, err := request.configuration()
	if err != nil {
		return nil, -1, err
	}
	local, err := validateIPv4Unicast(config.Address)
	if err != nil {
		return nil, -1, err
	}
	peer, err := validateIPv4Unicast(config.Peer)
	if err != nil {
		return nil, -1, err
	}
	if local == peer {
		return nil, -1, errors.New("the TUN address pair must be distinct")
	}
	if config.MTU < 68 || config.MTU > 65535 {
		return nil, -1, fmt.Errorf("mtu %d is outside the usable range", config.MTU)
	}
	prefixes := make([]netip.Prefix, 0, len(config.Prefixes))
	for _, text := range config.Prefixes {
		prefix, err := validatePrefix(text)
		if err != nil {
			return nil, -1, err
		}
		prefixes = append(prefixes, prefix)
	}

	// Detect the DNS mechanism before mutating anything so an unsupported
	// host fails without leaving a half-configured device behind.
	dnsMode := dnsModeSkipped
	if len(config.Domains) > 0 {
		dnsMode, err = detectDNSMode()
		if err != nil {
			return nil, -1, fmt.Errorf("automatic routing needs a supported DNS mechanism: %w", err)
		}
	}

	dev, err := openTUN()
	if err != nil {
		return nil, -1, err
	}
	device := &deviceInfo{Name: dev.name, Index: dev.index, MTU: config.MTU,
		Address: config.Address, Peer: config.Peer}
	fail := func(err error) (*deviceInfo, int, error) {
		dev.withdraw()
		clearState(s.uid)
		return nil, -1, err
	}

	if err := dev.configure(local, peer, config.MTU); err != nil {
		return fail(err)
	}

	// Write-ahead the ownership record before any mutation that can outlive
	// this process (DNS edits and routes).
	state := &ownedState{Version: stateVersion, UID: s.uid, PID: s.pid, Device: device}
	if err := saveState(state); err != nil {
		return fail(err)
	}

	if dnsMode != dnsModeSkipped {
		ownership, err := applyDNS(dnsMode, dev.name, config.Peer, config.Domains)
		if err != nil {
			return fail(err)
		}
		state.DNS = ownership
		if err := saveState(state); err != nil {
			return fail(err)
		}
	}

	for _, prefix := range prefixes {
		if err := dev.nl.addRoute(dev.index, prefix); err != nil {
			return fail(err)
		}
	}
	state.Prefixes = config.Prefixes
	if err := saveState(state); err != nil {
		return fail(err)
	}

	s.state, s.dev = state, dev
	return device, dev.fd, nil
}

// extend installs /32 host routes for addresses the core discovered on campus
// names (the DNS-route publisher path).
func (s *helperSession) extend(request *request) error {
	if s.state == nil || s.dev == nil {
		return errors.New("no active capture to extend")
	}
	var problems []string
	added := make([]string, 0, len(request.Addresses))
	for _, text := range request.Addresses {
		addr, err := validateIPv4Unicast(text)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		prefix := netip.PrefixFrom(addr, 32)
		if containsString(s.state.Dynamic, prefix.String()) || containsString(added, prefix.String()) {
			continue
		}
		if err := s.dev.nl.addRoute(s.dev.index, prefix); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		added = append(added, prefix.String())
	}
	s.state.Dynamic = append(s.state.Dynamic, added...)
	if err := saveState(s.state); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// reconcile replaces the static campus prefix set with the requested one.
func (s *helperSession) reconcile(request *request) error {
	if s.state == nil || s.dev == nil {
		return errors.New("no active capture to reconcile")
	}
	current := make(map[string]bool, len(s.state.Prefixes))
	for _, text := range s.state.Prefixes {
		current[text] = true
	}
	requested := make(map[string]bool, len(request.Prefixes))
	order := make([]string, 0, len(request.Prefixes))
	for _, text := range request.Prefixes {
		prefix, err := validatePrefix(text)
		if err != nil {
			return err
		}
		_ = prefix
		if !requested[text] {
			requested[text] = true
			order = append(order, text)
		}
	}
	var problems []string
	for _, text := range s.state.Prefixes {
		if requested[text] {
			continue
		}
		prefix, err := validatePrefix(text)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if err := s.dev.nl.delRoute(s.dev.index, prefix); err != nil {
			problems = append(problems, err.Error())
		}
	}
	for _, text := range order {
		if current[text] {
			continue
		}
		prefix, err := validatePrefix(text)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if err := s.dev.nl.addRoute(s.dev.index, prefix); err != nil {
			problems = append(problems, err.Error())
		}
	}
	s.state.Prefixes = order
	if err := saveState(s.state); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// restore withdraws the whole capture: DNS, routes, addresses, up flag. It is
// idempotent and safe to call repeatedly.
func (s *helperSession) restore() error {
	state := s.state
	if state == nil {
		return nil
	}
	var problems []string
	if err := withdrawDNS(state.DNS); err != nil {
		problems = append(problems, err.Error())
	}
	if device := state.Device; device != nil {
		if s.dev != nil {
			if err := s.dev.withdraw(); err != nil {
				problems = append(problems, err.Error())
			}
			s.dev = nil
		} else if err := withdrawRecordedState(state); err != nil {
			problems = append(problems, err.Error())
		}
	}
	s.state = nil
	if err := clearState(s.uid); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// withdrawRecordedState restores a session whose device descriptor is no
// longer held by this helper (leftover record or a closed device). The device
// may already be gone — a nonpersistent TUN dies with its last descriptor,
// taking its routes with it.
func withdrawRecordedState(state *ownedState) error {
	device := state.Device
	if device == nil {
		return withdrawDNS(state.DNS)
	}
	var problems []string
	if err := withdrawDNS(state.DNS); err != nil {
		problems = append(problems, err.Error())
	}
	iface, err := net.InterfaceByName(device.Name)
	if err != nil || iface.Index != device.Index {
		// Device vanished or the index was recycled; skip the device work.
	} else {
		nl, err := openNetlink()
		if err != nil {
			problems = append(problems, err.Error())
		} else {
			if err := nl.sweepRoutes(iface.Index); err != nil {
				problems = append(problems, err.Error())
			}
			if local, err := validateIPv4Unicast(device.Address); err == nil {
				if peer, err := validateIPv4Unicast(device.Peer); err == nil {
					if err := nl.delAddress(iface.Index, local, peer); err != nil {
						problems = append(problems, err.Error())
					}
				}
			}
			if err := nl.linkDown(iface.Index); err != nil {
				problems = append(problems, err.Error())
			}
			nl.close()
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

// sendReply writes one length-prefixed reply, optionally carrying the TUN
// descriptor via SCM_RIGHTS. It uses the raw descriptor: os.File.Fd() would
// flip the socket back to blocking mode and disable read deadlines.
func sendReply(connFD int, reply *response, attachFD int) error {
	data, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	if len(data) > maxRequestBytes {
		return errors.New("reply exceeds the protocol bound")
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	if attachFD >= 0 {
		rights := unix.UnixRights(attachFD)
		return unix.Sendmsg(connFD, frame, rights, nil, 0)
	}
	return writeAll(connFD, frame)
}

// malformedReply reconstructs as much of the envelope as possible so the
// application can attribute the failure.
func malformedReply(payload []byte, err error) *response {
	reply := &response{Version: helperProtocol, Status: statusFailed, Detail: err.Error()}
	var lenient struct {
		Operation string `json:"operation"`
		Owner     string `json:"owner"`
		RequestID string `json:"request_id"`
	}
	if json.Unmarshal(payload, &lenient) == nil {
		reply.Operation = lenient.Operation
		reply.Owner = lenient.Owner
		reply.RequestID = lenient.RequestID
	}
	return reply
}

func readFull(file *os.File, buf []byte) error {
	read := 0
	for read < len(buf) {
		n, err := file.Read(buf[read:])
		if err != nil {
			return err
		}
		if n == 0 {
			return io.EOF
		}
		read += n
	}
	return nil
}

func writeAll(connFD int, data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(connFD, data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
