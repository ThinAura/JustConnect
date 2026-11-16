//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInsertResolvNameserverPrependsOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	original := "# comment\nnameserver 192.168.1.1\nsearch example.edu\n"
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	line := "nameserver 10.22.4.2"
	if _, err := insertResolvNameserverAt(path, line); err != nil {
		t.Fatalf("insert: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := line + "\n" + original
	if string(data) != want {
		t.Fatalf("content %q, expected %q", data, want)
	}
	// Idempotent: the same peer inserts nothing.
	if _, err := insertResolvNameserverAt(path, line); err != nil {
		t.Fatalf("reinsert: %v", err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != want {
		t.Fatalf("reinsert changed the file to %q", data)
	}
	if err := removeResolvNameserver(path, line); err != nil {
		t.Fatalf("remove: %v", err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != original {
		t.Fatalf("restore left %q, expected the original content", data)
	}
}

func TestRemoveResolvNameserverToleratesMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 192.168.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := removeResolvNameserver(path, "nameserver 10.22.4.2"); err != nil {
		t.Fatalf("removing a foreign line must be a no-op: %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "nameserver 192.168.1.1\n" {
		t.Fatalf("file changed to %q", data)
	}
	if err := removeResolvNameserver(filepath.Join(dir, "missing.conf"), "nameserver 1.2.3.4"); err != nil {
		t.Fatalf("missing file must be tolerated: %v", err)
	}
}

func TestWriteResolvFilePreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 192.168.1.1\n"), 0640); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeResolvFile(path, "nameserver 10.22.4.2\n", info); err != nil {
		t.Fatalf("write: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != 0640 {
		t.Fatalf("mode changed to %v", after.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), "nameserver 10.22.4.2\n") {
		t.Fatalf("unexpected content %q", data)
	}
}

func TestDetectDNSModeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 192.168.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	mode, err := detectDNSModeAt(path)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if mode != dnsModeFile {
		t.Fatalf("mode %q, expected %q", mode, dnsModeFile)
	}
}

func TestDetectDNSModeMissingFile(t *testing.T) {
	if _, err := detectDNSModeAt(filepath.Join(t.TempDir(), "resolv.conf")); err == nil {
		t.Fatal("a missing resolv.conf must be reported as unusable")
	}
}

// The live host detection must agree with itself; the value is informational.
func TestDetectDNSModeLive(t *testing.T) {
	if _, err := detectDNSMode(); err != nil {
		t.Logf("host reports no usable DNS mechanism: %v", err)
	}
}
