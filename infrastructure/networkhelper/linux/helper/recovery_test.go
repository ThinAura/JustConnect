//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeNetlink records every device mutation and can fail route setup, so the
// rollback behavior of apply() is exercised without /dev/net/tun.
type fakeNetlink struct {
	routeErr    error
	routes      []netip.Prefix
	deleted     []netip.Prefix
	sweeps      int
	addresses   int
	addressesIn []netip.Addr
	downs       int
}

func (f *fakeNetlink) linkSetMTUUp(int, int) error { return nil }
func (f *fakeNetlink) addAddress(index int, local, peer netip.Addr) error {
	f.addresses++
	f.addressesIn = append(f.addressesIn, local, peer)
	return nil
}
func (f *fakeNetlink) addRoute(index int, prefix netip.Prefix) error {
	if f.routeErr != nil {
		return f.routeErr
	}
	f.routes = append(f.routes, prefix)
	return nil
}
func (f *fakeNetlink) delRoute(index int, prefix netip.Prefix) error {
	f.deleted = append(f.deleted, prefix)
	return nil
}
func (f *fakeNetlink) sweepRoutes(index int) error { f.sweeps++; return nil }
func (f *fakeNetlink) delAddress(index int, local, peer netip.Addr) error {
	f.addresses--
	return nil
}
func (f *fakeNetlink) linkDown(index int) error { f.downs++; return nil }

func fakeDevice(nl *fakeNetlink) *tunDevice {
	return &tunDevice{name: "tun-fake", index: 4242, fd: -1, nl: nl}
}

// applyFixture relocates every mutated path and installs the fake device.
type applyFixture struct {
	resolv   string
	original string
	nl       *fakeNetlink
	uid      int
	t        *testing.T
	// dnsHook lets a test observe or disturb the DNS application itself.
	dnsHook func(*dnsOwnership) error
}

func newApplyFixture(t *testing.T) *applyFixture {
	t.Helper()
	withStateRoot(t)
	directory := t.TempDir()
	f := &applyFixture{
		resolv:   filepath.Join(directory, "resolv.conf"),
		original: "nameserver 10.0.0.1\nnameserver 10.0.0.2\n",
		nl:       &fakeNetlink{},
		uid:      os.Getuid(),
		t:        t,
		dnsHook:  applyDNS,
	}
	if err := os.WriteFile(f.resolv, []byte(f.original), 0o644); err != nil {
		t.Fatal(err)
	}
	resolvConfPath = f.resolv
	if err := prepareStateDir(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resolvConfPath = "/etc/resolv.conf" })
	return f
}

func (f *applyFixture) apply(t *testing.T, prefixes []string) (*deviceInfo, int, error) {
	t.Helper()
	openTUNFn = func() (*tunDevice, error) { return fakeDevice(f.nl), nil }
	configureTUNFn = func(*tunDevice, netip.Addr, netip.Addr, int) error { return nil }
	t.Cleanup(func() {
		openTUNFn = openTUN
		configureTUNFn = func(d *tunDevice, local, peer netip.Addr, mtu int) error {
			return d.configure(local, peer, mtu)
		}
	})
	applyDNSFn = func(ownership *dnsOwnership) error {
		// The write-ahead contract: the record — including the DNS intent —
		// must be on disk before the first DNS mutation.
		state, err := loadState(f.uid)
		if err != nil || state == nil || state.DNS == nil {
			t.Errorf("DNS mutation started without a written ownership record (err=%v)", err)
		} else if state.DNS.Inserted != ownership.Inserted || state.DNS.ResolvPath != ownership.ResolvPath {
			t.Errorf("recorded DNS ownership does not match the applied plan: %+v vs %+v", state.DNS, ownership)
		}
		return f.dnsHook(ownership)
	}
	t.Cleanup(func() { applyDNSFn = applyDNS })
	session := &helperSession{uid: f.uid, pid: os.Getpid()}
	requestText, err := json.Marshal(map[string]any{
		"version": helperProtocol, "operation": opApply, "owner": testOwner, "request_id": testRequest,
		"address": "10.22.4.1", "peer": "10.22.4.2", "mtu": 1400,
		"prefixes": prefixes, "dns_domains": []string{"campus.example.edu"},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseRequest(requestText)
	if err != nil {
		t.Fatal(err)
	}
	return session.apply(parsed)
}

func (f *applyFixture) record(t *testing.T) *ownedState {
	t.Helper()
	state, err := loadState(f.uid)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	return state
}

// TestApplyRollsBackDNSWhenRouteSetupFails covers the reviewer scenario: a
// route setup failure after DNS changes must restore DNS too.
func TestApplyRollsBackDNSWhenRouteSetupFails(t *testing.T) {
	f := newApplyFixture(t)
	f.nl.routeErr = errors.New("route add refused: kernel says no")
	_, _, err := f.apply(t, []string{"10.50.0.0/16", "10.60.0.0/16"})
	if err == nil || !strings.Contains(err.Error(), "route add refused") {
		t.Fatalf("expected the route failure to surface, got %v", err)
	}
	data, err := os.ReadFile(f.resolv)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != f.original {
		t.Fatalf("DNS was not rolled back after the route failure: %q", string(data))
	}
	if record := f.record(t); record != nil {
		t.Fatalf("the ownership record survived a successful rollback: %+v", record)
	}
	if f.nl.sweeps == 0 || f.nl.downs == 0 {
		t.Fatalf("the fake device was not withdrawn (sweeps=%d downs=%d)", f.nl.sweeps, f.nl.downs)
	}
}

// TestApplyRetainsRecordWhenDNSRestoreFails covers the blocked-recovery
// scenario: if restoring DNS fails, the record is kept and a retry (or the
// next helper instance) can finish the cleanup.
func TestApplyRetainsRecordWhenDNSRestoreFails(t *testing.T) {
	f := newApplyFixture(t)
	f.nl.routeErr = errors.New("route add refused: kernel says no")
	// After DNS is applied, make the file unreadable so the restore fails.
	f.dnsHook = func(ownership *dnsOwnership) error {
		if err := applyDNS(ownership); err != nil {
			return err
		}
		if err := os.Remove(f.resolv); err != nil {
			t.Fatal(err)
		}
		// A directory at the recorded path makes every later read fail.
		if err := os.Mkdir(f.resolv, 0o755); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	_, _, err := f.apply(t, []string{"10.50.0.0/16"})
	if err == nil || !strings.Contains(err.Error(), "restore DNS also failed") {
		t.Fatalf("expected the DNS restore failure to surface, got %v", err)
	}
	record := f.record(t)
	if record == nil || record.DNS == nil || record.Device == nil {
		t.Fatalf("the ownership record was not retained for recovery: %+v", record)
	}
	if len(record.Prefixes) != 0 {
		t.Fatalf("a refused route setup must not be recorded as owned: %+v", record.Prefixes)
	}
}

// TestRestoreRetainsRecordOnFailure verifies restore() keeps the record when
// any withdrawal step fails, and clears it only on full success.
func TestRestoreRetainsRecordOnFailure(t *testing.T) {
	withStateRoot(t)
	if err := prepareStateDir(); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	unreadable := filepath.Join(directory, "blocked")
	if err := os.Mkdir(unreadable, 0o755); err != nil {
		t.Fatal(err)
	}
	withStateRoot(t)
	if err := prepareStateDir(); err != nil {
		t.Fatal(err)
	}
	session := &helperSession{uid: os.Getuid(), pid: os.Getpid()}
	session.dev = fakeDevice(&fakeNetlink{})
	session.state = &ownedState{
		Version: stateVersion, UID: session.uid, PID: session.pid,
		Device: &deviceInfo{Name: "tun-fake", Index: 4242},
		DNS:    &dnsOwnership{Mode: dnsModeFile, ResolvPath: unreadable, Inserted: "nameserver 10.22.4.2"},
	}
	if err := saveState(session.state); err != nil {
		t.Fatal(err)
	}
	if err := session.restore(); err == nil {
		t.Fatal("a failed DNS restore must be reported")
	}
	if session.state == nil {
		t.Fatal("the in-memory record was dropped although cleanup failed")
	}
	if record, err := loadState(session.uid); err != nil || record == nil {
		t.Fatalf("the on-disk record was not retained: %v %+v", err, record)
	}
	// Once the obstruction is gone the same record withdraws cleanly.
	if err := os.Remove(unreadable); err != nil {
		t.Fatal(err)
	}
	if err := session.restore(); err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	if record, err := loadState(session.uid); err != nil || record != nil {
		t.Fatalf("a successful cleanup must clear the record: %v %+v", err, record)
	}
}

// TestRecoverLeftoverStateRestoresAfterKill simulates a helper that was
// SIGKILLed mid-session: the record (DNS + device) outlives the process and
// the next instance must restore it before serving.
func TestRecoverLeftoverStateRestoresAfterKill(t *testing.T) {
	f := newApplyFixture(t)
	uid := f.uid
	line := "nameserver 10.22.4.2"
	if err := os.WriteFile(f.resolv, []byte(line+"\n"+f.original), 0o644); err != nil {
		t.Fatal(err)
	}
	record := &ownedState{
		Version: stateVersion, UID: uid, PID: os.Getpid(),
		Device: &deviceInfo{Name: "tun-crashed", Index: 9999}, // nonexistent device
		DNS: &dnsOwnership{
			Mode: dnsModeFile, ResolvPath: f.resolv, Inserted: line,
			Original: []string{"nameserver 10.0.0.1", "nameserver 10.0.0.2"},
		},
	}
	if err := saveState(record); err != nil {
		t.Fatal(err)
	}
	if err := recoverLeftoverState(uid); err != nil {
		t.Fatalf("leftover recovery failed: %v", err)
	}
	data, err := os.ReadFile(f.resolv)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != f.original {
		t.Fatalf("the crashed helper's DNS edit was not withdrawn: %q", string(data))
	}
	if state, err := loadState(uid); err != nil || state != nil {
		t.Fatalf("the recovered record was not cleared: %v %+v", err, state)
	}
}

// TestRecoverLeftoverStateRestoresRemovedNameservers covers DNS entries that
// were already present before the connection and were removed while the
// capture owned the file.
func TestRecoverLeftoverStateRestoresRemovedNameservers(t *testing.T) {
	f := newApplyFixture(t)
	uid := f.uid
	line := "nameserver 10.22.4.2"
	if err := os.WriteFile(f.resolv, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	record := &ownedState{
		Version: stateVersion, UID: uid, PID: os.Getpid(),
		DNS: &dnsOwnership{
			Mode: dnsModeFile, ResolvPath: f.resolv, Inserted: line,
			Original: []string{"nameserver 10.0.0.1", "nameserver 10.0.0.2"},
		},
	}
	if err := saveState(record); err != nil {
		t.Fatal(err)
	}
	if err := recoverLeftoverState(uid); err != nil {
		t.Fatalf("leftover recovery failed: %v", err)
	}
	data, err := os.ReadFile(f.resolv)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "nameserver 10.0.0.1") || !strings.Contains(content, "nameserver 10.0.0.2") {
		t.Fatalf("pre-connection nameserver entries were not preserved: %q", content)
	}
	if strings.Contains(content, line) {
		t.Fatalf("the owned nameserver line survived the restore: %q", content)
	}
}

// TestRecoverLeftoverStateBlocksOnFailedRestore: an unrestorable record keeps
// blocking new connections until the cleanup succeeds.
func TestRecoverLeftoverStateBlocksOnFailedRestore(t *testing.T) {
	f := newApplyFixture(t)
	uid := f.uid
	record := &ownedState{
		Version: stateVersion, UID: uid, PID: os.Getpid(),
		DNS: &dnsOwnership{
			Mode: dnsModeFile, ResolvPath: filepath.Join(f.resolv, "missing-parent"), Inserted: "nameserver 10.22.4.2",
			Original: []string{"nameserver 10.0.0.1"},
		},
	}
	if err := saveState(record); err != nil {
		t.Fatal(err)
	}
	if err := recoverLeftoverState(uid); err == nil {
		t.Fatal("an unrestorable record must fail the recovery")
	}
	if state, err := loadState(uid); err != nil || state == nil {
		t.Fatalf("the failed recovery must retain the record: %v %+v", err, state)
	}
}

// TestApplyRefusesWhileRecordRetained: a retry must not overwrite a retained
// record; the probe cleans it up first.
func TestApplyRefusesWhileRecordRetained(t *testing.T) {
	f := newApplyFixture(t)
	record := &ownedState{
		Version: stateVersion, UID: f.uid, PID: os.Getpid(),
		DNS: &dnsOwnership{Mode: dnsModeFile, ResolvPath: f.resolv, Inserted: "nameserver 10.22.4.2"},
	}
	if err := saveState(record); err != nil {
		t.Fatal(err)
	}
	_, _, err := f.apply(t, []string{"10.50.0.0/16"})
	if err == nil || !strings.Contains(err.Error(), "uncleaned ownership record") {
		t.Fatalf("expected the apply to be refused, got %v", err)
	}
	if state, err := loadState(f.uid); err != nil || state == nil {
		t.Fatalf("the retained record was damaged: %v %+v", err, state)
	}
}

// TestServeProbeCleansLeftoverRecord: the probe recovers a retained record
// and reports the DNS mode only afterwards.
func TestServeProbeCleansLeftoverRecord(t *testing.T) {
	f := newApplyFixture(t)
	line := "nameserver 10.22.4.2"
	if err := os.WriteFile(f.resolv, []byte(line+"\n"+f.original), 0o644); err != nil {
		t.Fatal(err)
	}
	record := &ownedState{
		Version: stateVersion, UID: f.uid, PID: os.Getpid(),
		DNS: &dnsOwnership{
			Mode: dnsModeFile, ResolvPath: f.resolv, Inserted: line,
			Original: []string{"nameserver 10.0.0.1"},
		},
	}
	if err := saveState(record); err != nil {
		t.Fatal(err)
	}
	client, _ := newTestClient(t)
	client.send(t, envelope(opProbe))
	reply := client.receive(t)
	if reply.Status != statusOK {
		t.Fatalf("probe with a cleanable leftover record failed: %+v", reply)
	}
	data, err := os.ReadFile(f.resolv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), line) {
		t.Fatalf("the probe did not withdraw the leftover DNS edit: %q", string(data))
	}
	client.send(t, envelope(opClose))
	if reply := client.receive(t); reply.Status != statusOK {
		t.Fatalf("close after leftover cleanup: %+v", reply)
	}
	client.expectClosed(t)
}

// TestServeProbeFailsWhileRecordUnrestorable: an unrestorable record keeps
// the probe (and therefore every new connection) blocked.
func TestServeProbeFailsWhileRecordUnrestorable(t *testing.T) {
	f := newApplyFixture(t)
	record := &ownedState{
		Version: stateVersion, UID: f.uid, PID: os.Getpid(),
		DNS: &dnsOwnership{
			Mode: dnsModeFile, ResolvPath: filepath.Join(f.resolv, "blocked"), Inserted: "nameserver 10.22.4.2",
		},
	}
	if err := saveState(record); err != nil {
		t.Fatal(err)
	}
	client, _ := newTestClient(t)
	client.send(t, envelope(opProbe))
	reply := client.receive(t)
	if reply.Status == statusOK {
		t.Fatalf("the probe ignored an unrestorable record: %+v", reply)
	}
	client.send(t, envelope(opClose))
	if reply := client.receive(t); reply.Status != statusOK {
		t.Fatalf("close after failed probe: %+v", reply)
	}
	client.expectClosed(t)
}
