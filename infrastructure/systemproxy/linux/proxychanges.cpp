#include "infrastructure/systemproxy/proxychanges.h"
#include "infrastructure/process/command.h"
#include <QTimer>

// dconf exposes no Qt-visible change notification; poll the managed keys and emit on value movement.
struct ProxyChanges::Watch {
    QTimer timer;
    QStringList keys;
    QByteArray previous;
};

namespace {
QStringList managedKeys()
{
    return {
        "org.gnome.system.proxy/mode", "org.gnome.system.proxy/autoconfig-url", "org.gnome.system.proxy/ignore-hosts",
        "org.gnome.system.proxy.http/host", "org.gnome.system.proxy.http/port",
        "org.gnome.system.proxy.https/host", "org.gnome.system.proxy.https/port",
        "org.gnome.system.proxy.ftp/host", "org.gnome.system.proxy.ftp/port",
        "org.gnome.system.proxy.socks/host", "org.gnome.system.proxy.socks/port"};
}

QByteArray readValues(const QStringList &keys)
{
    QByteArray joined;
    for (const auto &key : keys) {
        const auto separator = key.indexOf('/');
        const auto value = runPlatformCommand(QStringLiteral("gsettings"),
            {QStringLiteral("get"), key.left(separator), key.mid(separator + 1)});
        if (!value.result.succeeded()) return {};
        joined += key.toUtf8() + '=' + value.output.toUtf8() + '\n';
    }
    return joined;
}
}

ProxyChanges::ProxyChanges(QObject *parent) : QObject(parent), watch(std::make_unique<Watch>()) {
    watch->keys = managedKeys();
    const auto initial = readValues(watch->keys);
    if (initial.isEmpty()) return; // No usable gsettings session: stay silent instead of spinning.
    watch->previous = initial;
    constexpr int PollIntervalMs = 2000;
    watch->timer.setInterval(PollIntervalMs);
    QObject::connect(&watch->timer, &QTimer::timeout, this, [this] {
        const auto current = readValues(watch->keys);
        if (current.isEmpty()) return; // A transient failure never reports a proxy change.
        if (current == watch->previous) return;
        watch->previous = current;
        emit changed();
    });
    watch->timer.start();
}

ProxyChanges::~ProxyChanges() = default;
