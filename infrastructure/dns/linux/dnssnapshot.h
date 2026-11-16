#pragma once
#include "infrastructure/dns/dnssnapshot.h"

inline constexpr qsizetype LinuxDnsSnapshotBytes = 262144;

// Reads /etc/resolv.conf (with systemd-resolved upstreams behind a stub listener).
DnsSnapshot readLinuxDnsSnapshot();
