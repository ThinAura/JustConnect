#!/bin/bash
# Build the Debian package from a configured build tree.
#
# The payload is deliberately minimal: everything outside the two binaries
# (the privileged network helper) is delivered as Debian package
# dependencies — system Qt, WebKitGTK, libsecret, polkit — because the app
# dlopens or links against the distribution libraries directly. The helper
# must be root-owned for pkexec, which dpkg guarantees on install.
#
# The build tree must be configured with -DCMAKE_INSTALL_PREFIX=/usr so the
# helper path compiled into the application (and annotated in the polkit
# policy) matches the installed location /usr/libexec/justconnect-network-helper.
#
# Usage: scripts/package-deb.sh <build-dir> <output.deb> [version]
set -euo pipefail

build="${1:?Specify the build directory}"
output="${2:?Specify the output .deb path}"
version="${3:-}"

command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required to build the Debian package" >&2; exit 1; }
command -v cmake >/dev/null || { echo "cmake is required to stage the install tree" >&2; exit 1; }

repo="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -z "$version" ]]; then
    version="$(git -C "$repo" describe --tags --match 'v*' 2>/dev/null | sed -e 's/^v//' -e 's/-[0-9]*-g[0-9a-f]*$//')-1" || version="0.0.0-1"
fi

# Debian versions must start with a digit. Snapshot identifiers such as
# 'f70134c-nightly' gain a '0.0.0~' prefix, which Debian's version ordering
# keeps below every real release.
if [[ ! "$version" =~ ^[0-9] ]]; then
    version="0.0.0~${version}"
fi

stage="$(mktemp -d "${TMPDIR:-/tmp}/justconnect-deb.XXXXXX")"
cleanup() { rm -rf "$stage"; }
trap cleanup EXIT

# Stage the CMake install tree under the Debian root.
DESTDIR="$stage" cmake --install "$build" --prefix /usr >/dev/null

# Relocate licenses into the Debian documentation directory; drop
# portable-package artifacts that do not belong in a system install.
doc="$stage/usr/share/doc/justconnect"
mkdir -p "$doc"
mv "$stage/usr/licenses/LICENSE" "$doc/copyright"
mv "$stage/usr/licenses/ThirdPartyNotices.txt" "$stage/usr/licenses/LICENSE.lucide" \
   "$stage/usr/licenses/LICENSE.ping" "$doc/"
rmdir "$stage/usr/licenses"
rm -f "$stage/usr/core-toolchain.txt" "$stage/usr/source-revision.txt" "$stage/usr/setup-network-helper.sh"

# Sanity: the compiled-in helper path and the polkit annotation must match
# the installed location, or pkexec falls back to its generic prompt.
policy="$stage/usr/share/polkit-1/actions/org.justconnect.network-helper.policy"
helper_path="/usr/libexec/justconnect-network-helper"
grep -q "$helper_path" "$policy" || { echo "polkit policy does not annotate $helper_path; configure with -DCMAKE_INSTALL_PREFIX=/usr" >&2; exit 1; }
grep -rq "$helper_path" "$stage/usr/bin/JustConnect" || { echo "application does not embed $helper_path; configure with -DCMAKE_INSTALL_PREFIX=/usr" >&2; exit 1; }

installed_size="$(du -sk --apparent-size "$stage/usr" | cut -f1)"

mkdir -p "$stage/DEBIAN"
cat > "$stage/DEBIAN/control" <<EOF
Package: justconnect
Version: $version
Architecture: amd64
Maintainer: ThinAura <260574842+ThinAura@users.noreply.github.com>
Installed-Size: $installed_size
Depends: libdconf1, libqt6core6t64, libqt6dbus6, libqt6gui6, libqt6network6, libqt6svg6, libqt6widgets6, libsecret-1-0, libwebkit2gtk-4.1-0, pkexec, qt6-svg-plugins, qt6-wayland
Recommends: fonts-dejavu-core, systemd-resolved
Section: net
Priority: optional
Homepage: https://github.com/wtalioy/JustConnect
Description: Connect to aTrust campus VPN gateways
 JustConnect signs in to campus SSO (WebKitGTK browser), routes campus
 traffic through a privileged network helper (polkit) or a local proxy,
 and restores system proxy state after crashes. Saved sign-ins persist
 through the Secret Service keyring (libsecret) with a 0600-file
 fallback when no keyring is available.
EOF

# md5sums of the payload, paths relative to the package root.
( cd "$stage" && find usr -type f -exec md5sum {} + | sed 's|  \./|  |' | sort -k2 ) > "$stage/DEBIAN/md5sums"

# Normalize permissions: directories 0755, data files 0644; dpkg-deb applies
# root ownership with --root-owner-group.
find "$stage/usr" -type d -exec chmod 0755 {} +
chmod 0755 "$stage" "$stage/DEBIAN"
chmod 0644 "$stage/DEBIAN/control" "$stage/DEBIAN/md5sums"
dpkg-deb --build --root-owner-group "$stage" "$output" 1>&2
echo "$output"
