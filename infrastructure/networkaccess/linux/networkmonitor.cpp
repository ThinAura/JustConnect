#include "infrastructure/networkaccess/linux/networkmonitor.h"
#include <QDir>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <memory>

namespace {
// Groups that cover everything the protection checks observe: the default
// exit (routes, interfaces, addresses) and the resolver snapshot (file edits
// surface through the file watcher; a resolv.conf replacement also shows up
// as filesystem activity).
constexpr unsigned NetlinkGroups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;

// Coalesce a burst of kernel events (a DHCP renew, a link flap) into one
// refresh request.
constexpr int CoalesceMs = 250;

QStringList watchedResolverPaths()
{
    QStringList paths;
    for (const auto &path : {QStringLiteral("/etc/resolv.conf"),
                             QStringLiteral("/run/systemd/resolve/resolv.conf"),
                             QStringLiteral("/run/systemd/resolve/stub-resolv.conf")}) {
        const QFileInfo info(path);
        if (info.exists() || info.isSymLink()) paths.append(path);
    }
    if (QDir(QStringLiteral("/run/systemd/resolve")).exists()) paths.append(QStringLiteral("/run/systemd/resolve"));
    return paths;
}
}

LinuxNetworkMonitor::LinuxNetworkMonitor(int monitorFd, QObject *parent)
    : QObject(parent)
{
    int fd = monitorFd;
    if (fd < 0) {
        fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0) return; // Without kernel notifications the session simply stops auto-refreshing.
        sockaddr_nl address{};
        address.nl_family = AF_NETLINK;
        address.nl_groups = NetlinkGroups;
        if (::bind(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
            ::close(fd);
            return;
        }
    }
    notifier = std::make_unique<QSocketNotifier>(fd, QSocketNotifier::Type::Read, this);
    notifier->setEnabled(true);
    connect(notifier.get(), &QSocketNotifier::activated, this, [this] { schedule(); });

    coalesce.setSingleShot(true);
    coalesce.setInterval(CoalesceMs);
    connect(&coalesce, &QTimer::timeout, this, &LinuxNetworkMonitor::networkChanged);

    const auto paths = watchedResolverPaths();
    if (!paths.isEmpty()) {
        connect(&files, &QFileSystemWatcher::fileChanged, this, [this](const QString &) { schedule(); });
        connect(&files, &QFileSystemWatcher::directoryChanged, this, [this](const QString &) { schedule(); });
        files.addPaths(paths);
    }
}

LinuxNetworkMonitor::~LinuxNetworkMonitor()
{
    const int fd = notifier ? notifier->socket() : -1;
    if (fd >= 0) ::close(fd);
}

void LinuxNetworkMonitor::schedule()
{
    // Drain the socket so the notifier stops firing while the coalescer runs.
    const int socket = notifier ? notifier->socket() : -1;
    if (socket >= 0) {
        char buffer[8192];
        while (::recv(socket, buffer, sizeof(buffer), MSG_DONTWAIT) > 0) {
        }
    }
    coalesce.start();
}
