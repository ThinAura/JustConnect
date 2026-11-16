#!/bin/sh
# Make the bundled privileged network helper (libexec/justconnect-network-helper)
# executable by pkexec so automatic (TUN) routing works after extracting this
# package. Extraction recreates libexec/ with the extractor's ownership, and
# pkexec-eligible helpers must be root-owned, so this script runs once after
# every extraction or package update (see docs/build-linux.md).
#
# Routes:
#   sudo ./setup-network-helper.sh            make the shipped copy root-owned in place
#   sudo ./setup-network-helper.sh --system   install it to /usr/local/libexec
#                                             plus the polkit action
set -eu

die() { echo "setup-network-helper: $*" >&2; exit 1; }

package="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
helper="$package/libexec/justconnect-network-helper"
policy="$package/share/polkit-1/actions/org.justconnect.network-helper.policy"
system_helper="/usr/local/libexec/justconnect-network-helper"
system_policy="/usr/share/polkit-1/actions/org.justconnect.network-helper.policy"

mode="${1:---in-place}"
if [ "$mode" != "--in-place" ] && [ "$mode" != "--system" ]; then
    die "unknown option: $mode (usage: sudo $0 [--in-place|--system])"
fi
[ "$(id -u)" = 0 ] || die "needs root to install or change ownership: run 'sudo $0 $mode'"
[ -f "$helper" ] || die "missing helper: $helper"

if [ "$mode" = "--system" ]; then
    install -D -o root -g root -m 0755 "$helper" "$system_helper"
    if [ -f "$policy" ]; then
        install -D -o root -g root -m 0644 "$policy" "$system_policy"
    else
        echo "setup-network-helper: $policy is missing; pkexec falls back to its generic prompt" >&2
    fi
    echo "Installed the network helper for system-wide use:"
    ls -l "$system_helper"
    echo
    echo "Rerun this script after every package update so the installed helper"
    echo "matches the application's helper protocol."
else
    chown root:root "$helper"
    chmod 0755 "$helper"
    echo "Made the bundled network helper pkexec-eligible:"
    ls -l "$helper"
    echo
    echo "Re-extracting this package recreates the helper with your own"
    echo "ownership; rerun this script after every update."
fi

"$helper" --version
echo "The helper above reports its identity; automatic routing can now request administrator privileges."
