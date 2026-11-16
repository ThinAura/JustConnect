# Building JustConnect on Linux

Linux supports both routing modes. **Automatic routing** creates a TUN device
through a privileged helper (`justconnect-network-helper`): once per
application start, polkit (`pkexec`) asks for the administrator password, and
the helper installs campus routes plus split DNS for the lifetime of the
session. Hosts need either systemd-resolved or a plain writable
`/etc/resolv.conf`; anything else is reported before connecting and automatic
mode stays unavailable. **Local proxy only** needs no privileges. Everything
else — sign-in (including the SSO browser), saved credentials, system proxy
hand-off and recovery, Clash coexistence — behaves like the Windows and macOS
builds.

## Prerequisites

| Tool | Version | Notes |
| --- | --- | --- |
| GCC / Clang + binutils | any recent | C++17, cgo compiler |
| CMake | 3.20+ | Ninja recommended |
| Qt | 6.10 – 6.12 | must include `WebEngineWidgets` |
| Go | **exactly** the version pinned in `corelib/go.mod` | the build sets `GOTOOLCHAIN=local` and rejects other versions |
| Python 3 | 3.9+ | packaging/verification helpers |
| patchelf | any | only needed for packaging |

On Ubuntu 24.04 (glibc 2.39) the distribution Qt is 6.4 — too old. Install Qt
6.10+ from the Qt SDK instead (see below). Package builds target Ubuntu 24.04
as the runtime floor; older distributions need newer glibc/fontconfig than
they ship.

### Distribution packages

```sh
sudo apt-get install -y build-essential cmake ninja-build python3 \
  libgl1-mesa-dev libegl-dev libxkbcommon-dev libfontconfig1-dev \
  libnss3-dev libxcomposite-dev libxcursor-dev libxi-dev libxtst-dev \
  libxrandr-dev libdrm-dev libgbm-dev libasound2-dev libatspi2.0-dev
```

`libnss3` is required at runtime by the QtWebEngine sign-in browser.

### Qt SDK

Use [aqtinstall](https://github.com/miurahr/aqtinstall) or the Qt online
installer. The build needs `qtbase qtsvg qtdeclarative qttools
qttranslations qtwebchannel qtpositioning qtwebengine`:

```sh
python3 -m pip install aqtinstall
aqt install-qt linux desktop 6.12.0 linux_gcc_64 \
  -m qtwebchannel qtpositioning qtwebengine -O ~/Qt
```

> aqt's architecture name is `linux_gcc_64` (new-style naming); the SDK still
> unpacks into `~/Qt/6.12.0/gcc_64`.

### Go

Install the exact Go version from `corelib/go.mod` (currently **1.27.2**),
e.g. from <https://go.dev/dl/>. `GOTOOLCHAIN=local` is enforced by the build,
so a newer Go installed locally will be rejected.

## Configure, build, test

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
  -DCMAKE_PREFIX_PATH="$HOME/Qt/6.12.0/gcc_64"
cmake --build build
```

Run the test suite (Qt tests use the `offscreen` platform; the QtWebEngine
tests need Chromium flags on CI-like sandboxed environments):

```sh
QT_QPA_PLATFORM=offscreen \
QTWEBENGINE_CHROMIUM_FLAGS='--no-sandbox --disable-gpu --disable-dev-shm-usage' \
  ctest --test-dir build --output-on-failure
```

## Install

A system install places the binary, the system-proxy recovery worker, the
desktop entry and the icon into the usual GNU directories:

```sh
sudo cmake --install build --prefix /usr/local
```

`JustConnectProxyRecovery` restores gsettings proxy state after crashes; it
needs no extra privileges on Linux.

### Privileged network helper (automatic routing)

`cmake --install` also places the privileged helper into
`<prefix>/libexec/justconnect-network-helper` (mode 0755, owned by root when
run under sudo) and the polkit action into
`<prefix>/share/polkit-1/actions/org.justconnect.network-helper.policy`.
polkit only reads actions from the directories it was built with, so make sure
the policy ends up in one of them (on most distributions
`/usr/share/polkit-1/actions`):

```sh
sudo cmake --install build --prefix /usr/local
sudo install -D -o root -g root -m 0644 \
    /usr/local/share/polkit-1/actions/org.justconnect.network-helper.policy \
    /usr/share/polkit-1/actions/
```

`pkexec` refuses to execute programs it does not own, so the helper must stay
root-owned and not group- or world-writable. The application checks this up
front: when no usable helper is found, automatic routing is reported as
unavailable with a diagnostic that names the exact commands (the same steps
appear on the server settings page) instead of failing after the password
prompt.

## Package (portable tarball)

The shipped Linux artifact is a portable, self-contained tree with bundled
Qt libraries, plugins and QtWebEngine resources:

```sh
./scripts/deploy-linux.sh JustConnect build "$HOME/Qt/6.12.0/gcc_64"
tar --sort=name --owner=0 --group=0 --numeric-owner -czf justconnect-linux-x64.tar.gz JustConnect
```

Users extract the tarball and run `bin/JustConnect`. **Automatic routing**
additionally needs its helper to be executable by `pkexec`, which refuses
user-owned files — either make the shipped copy root-owned in place:

```sh
sudo chown root:root JustConnect/libexec/justconnect-network-helper
sudo chmod 0755 JustConnect/libexec/justconnect-network-helper
```

or install it (plus the policy, for the exact polkit message) into system
locations:

```sh
sudo install -D -o root -g root -m 0755 \
    JustConnect/libexec/justconnect-network-helper /usr/local/libexec/justconnect-network-helper
sudo install -D -o root -g root -m 0644 \
    JustConnect/share/polkit-1/actions/org.justconnect.network-helper.policy \
    /usr/share/polkit-1/actions/
```

The package ships a `setup-network-helper.sh` script at its root that runs
either of these routes for you. It needs rerunning after every extraction or
package update, because extraction recreates `libexec/` with the extractor's
ownership:

```sh
sudo ./setup-network-helper.sh            # make the shipped copy root-owned in place
sudo ./setup-network-helper.sh --system   # install to /usr/local/libexec plus the policy
```

The policy annotation names the helper path recorded at build time; when it
does not match where `pkexec` actually runs the helper from, polkit falls back
to its default `auth_admin` prompt with a generic message — authorization
still works, only the prompt text is less specific.

The deploy script fails rather than ships an unresolvable package (every ELF
is checked with `ldd`); `scripts/verify-package.py` is what CI runs against
the final archive — it exercises the offline core self-test, the recovery
worker, the sign-in browser probe and the privileged network helper inside
the extracted tree.

## Runtime notes

- **System proxy** integration drives gsettings/dconf (`org.gnome.system.proxy`).
  It applies when a compatible desktop session is present; without one, the
  backend reports unsupported and local proxy keeps working.
- **Credential storage** uses libsecret when available and falls back to a
  0600 file next to the app data otherwise.
- **Autostart** writes an XDG autostart entry under `$XDG_CONFIG_HOME`.
- **SSO sign-in browser** uses QtWebEngine. On Ubuntu 23.10+ unprivileged
  user namespaces are restricted by default, which can prevent the Chromium
  sandbox from starting; launch with
  `QTWEBENGINE_CHROMIUM_FLAGS=--no-sandbox` (or install an AppArmor profile
  for the binary) if the sign-in browser fails to open.
- Wayland sessions run through XWayland (the packaged Qt build ships the xcb
  platform plugin).
