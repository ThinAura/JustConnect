//go:build linux

// DNS ownership for the privileged helper. Linux hosts vary widely: the core
// answers queries sent to the TUN peer address, so reaching that address is
// the host's job. Two mechanisms are supported:
//
//   - systemd-resolved: per-link split DNS via resolvectl (dns + route-only
//     routing domains on the TUN interface), withdrawn with `revert`.
//   - a plain /etc/resolv.conf (glibc, dnscrypt-proxy, dnsmasq, ...): one
//     `nameserver <peer>` line prepended to the file. Campus names are
//     answered by the core; every other name gets REFUSED, which glibc-class
//     resolvers treat as "try the next nameserver", so original resolution
//     keeps working. Restore removes exactly the inserted line.
//
// Anything else (missing or non-regular resolv.conf, resolved without
// resolvectl) is reported as unavailable so the application can tell the user
// automatic mode cannot run before starting a connection.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	dnsModeSkipped  = ""
	dnsModeResolved = "resolved"
	dnsModeFile     = "file"

	resolvConfPath   = "/etc/resolv.conf"
	resolvedStubLine = "nameserver 127.0.0.53"
	resolvedRunDir   = "/run/systemd/resolve"
)

// dnsOwnership records exactly what was mutated so the session can withdraw
// it later, including after a helper restart (the state file keeps it).
type dnsOwnership struct {
	Mode       string   `json:"mode"`
	Iface      string   `json:"interface,omitempty"`
	Peer       string   `json:"peer,omitempty"`
	Domains    []string `json:"domains,omitempty"`
	ResolvPath string   `json:"resolv_path,omitempty"`
	Inserted   string   `json:"inserted,omitempty"`
}

// detectDNSMode decides which DNS mechanism this host offers, or fails with a
// user-presentable reason when none is usable.
func detectDNSMode() (string, error) {
	return detectDNSModeAt(resolvConfPath)
}

func detectDNSModeAt(resolvPath string) (string, error) {
	real, err := filepath.EvalSymlinks(resolvPath)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", resolvPath, err)
	}
	if strings.HasPrefix(real, resolvedRunDir+"/") {
		if _, err := exec.LookPath("resolvectl"); err != nil {
			return "", errors.New("systemd-resolved is active but resolvectl is missing")
		}
		return dnsModeResolved, nil
	}
	if data, err := os.ReadFile(real); err == nil && strings.Contains(string(data), resolvedStubLine) {
		if _, err := exec.LookPath("resolvectl"); err != nil {
			return "", errors.New("systemd-resolved is active but resolvectl is missing")
		}
		return dnsModeResolved, nil
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", resolvPath, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file; no supported DNS mechanism was found", resolvPath)
	}
	return dnsModeFile, nil
}

// applyDNS installs campus DNS on the freshly configured TUN interface.
func applyDNS(mode, iface, peer string, domains []string) (*dnsOwnership, error) {
	ownership := &dnsOwnership{
		Mode:    mode,
		Iface:   iface,
		Peer:    peer,
		Domains: append([]string{}, domains...),
	}
	switch mode {
	case dnsModeResolved:
		if err := runCommand("resolvectl", "dns", iface, peer); err != nil {
			return nil, fmt.Errorf("set per-link DNS server: %w", err)
		}
		args := []string{"domain", iface}
		for _, domain := range domains {
			args = append(args, "~"+domain)
		}
		if err := runCommand("resolvectl", args...); err != nil {
			// Withdraw the half-applied per-link settings.
			_ = runCommand("resolvectl", "revert", iface)
			return nil, fmt.Errorf("set per-link routing domains: %w", err)
		}
	case dnsModeFile:
		// Domains need no installation here: glibc-class resolvers try the
		// first nameserver for every query and fall through on REFUSED.
		line := "nameserver " + peer
		path, err := insertResolvNameserver(line)
		if err != nil {
			return nil, fmt.Errorf("update %s: %w", resolvConfPath, err)
		}
		ownership.ResolvPath = path
		ownership.Inserted = line
	default:
		return nil, fmt.Errorf("unsupported DNS mode %q", mode)
	}
	return ownership, nil
}

// withdrawDNS undoes applyDNS. Best effort: a vanished interface already
// released its per-link settings, and a missing resolv.conf needs no edit.
func withdrawDNS(ownership *dnsOwnership) error {
	if ownership == nil || ownership.Mode == dnsModeSkipped {
		return nil
	}
	switch ownership.Mode {
	case dnsModeResolved:
		if err := runCommand("resolvectl", "revert", ownership.Iface); err != nil {
			if ifaceExists(ownership.Iface) {
				return fmt.Errorf("revert per-link DNS: %w", err)
			}
		}
	case dnsModeFile:
		if err := removeResolvNameserver(ownership.ResolvPath, ownership.Inserted); err != nil {
			return fmt.Errorf("restore %s: %w", resolvConfPath, err)
		}
	}
	return nil
}

func ifaceExists(name string) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", name))
	return err == nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "),
			err, strings.TrimSpace(string(output)))
	}
	return nil
}

// resolvNameserverLines returns the file's logical lines.
func resolvNameserverLines(data []byte) []string {
	return strings.Split(string(data), "\n")
}

// insertResolvNameserver prepends one nameserver line to /etc/resolv.conf
// (idempotent) and returns the real path it edited.
func insertResolvNameserver(line string) (string, error) {
	real, err := filepath.EvalSymlinks(resolvConfPath)
	if err != nil {
		return "", err
	}
	return insertResolvNameserverAt(real, line)
}

func insertResolvNameserverAt(path, line string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, existing := range resolvNameserverLines(data) {
		if existing == line || existing == line+"\r" {
			return path, nil
		}
	}
	updated := append([]string{line}, resolvNameserverLines(data)...)
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if err := writeResolvFile(path, strings.Join(updated, "\n"), info); err != nil {
		return "", err
	}
	return path, nil
}

// removeResolvNameserver deletes exactly the line previously inserted.
func removeResolvNameserver(path, line string) error {
	if path == "" || line == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	lines := resolvNameserverLines(data)
	removed := false
	out := make([]string, 0, len(lines))
	for _, existing := range lines {
		if !removed && (existing == line || existing == line+"\r") {
			removed = true
			continue
		}
		out = append(out, existing)
	}
	if !removed {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return writeResolvFile(path, strings.Join(out, "\n"), info)
}

// writeResolvFile publishes new content atomically, preserving mode and
// owner. A bind-mounted /etc/resolv.conf (containers) rejects rename, so an
// in-place write is the fallback.
func writeResolvFile(path, content string, info os.FileInfo) error {
	tmp := filepath.Join(filepath.Dir(path), fmt.Sprintf(".resolv.conf.justconnect-%d", os.Getpid()))
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, info.Mode().Perm())
	if err != nil {
		return err
	}
	if err := f.Chmod(info.Mode().Perm()); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := f.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return writeResolvInPlace(path, content)
	}
	return nil
}

func writeResolvInPlace(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
