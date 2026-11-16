#pragma once
#include "application/networkpolicysession.h"
#include "infrastructure/networkhelper/linux/networkhelperprotocol.h"

// This read-only projection grants no authority to restore native state.
// The filter subtracts the helper-owned TUN interface, its route rows and,
// in file DNS mode, the prepended peer nameserver from the observed snapshot.
// The device row is subtracted by its name and index identity regardless of
// the administrative up flag: desktop network managers briefly flip foreign
// TUN devices while adopting them, and the packet queue rides the borrowed
// descriptor either way.
NetworkPolicySession::OriginalViewFilter linuxOriginalNetworkView(const LinuxHelperConfiguration &configuration,
    const LinuxHelperDevice &device, const QString &dnsMode);

// True while the host's DNS snapshot still matches the ownership the helper
// installed; a mismatch means campus name resolution cannot work anymore.
bool linuxOriginalDnsMatches(const LinuxHelperConfiguration &configuration, const QString &dnsMode,
    const QJsonObject &dns);
