#pragma once
#include <QObject>
#include <QFileSystemWatcher>
#include <QSocketNotifier>
#include <QTimer>
#include <memory>

// Event-driven signals that the original network may have changed: kernel
// link, address and route notifications over one netlink socket, plus edits
// to the resolver files. This replaces periodic full-snapshot polling, so an
// unchanged connection never triggers a refresh and every real change does.
class LinuxNetworkMonitor final : public QObject
{
    Q_OBJECT
public:
    // monitorFd is a test seam: a connected datagram socket stands in for the
    // netlink route socket. Pass -1 to open the real one.
    explicit LinuxNetworkMonitor(int monitorFd, QObject *parent = nullptr);
    ~LinuxNetworkMonitor() override;

signals:
    void networkChanged();

private:
    void schedule();

    // Created only after the netlink socket is up; absent when kernel
    // notifications are unavailable.
    std::unique_ptr<QSocketNotifier> notifier;
    QTimer coalesce;
    QFileSystemWatcher files;
};
