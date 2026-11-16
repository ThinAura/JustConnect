#include "infrastructure/networkhelper/linux/networkhelperavailability.h"
#include "infrastructure/networkhelper/linux/networkhelperpaths.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>

namespace {
enum class DnsMechanism { Unavailable, Resolved, PlainFile };

DnsMechanism detectDnsMechanism(QString *detail)
{
    // Same taxonomy as the privileged helper (infrastructure/networkhelper/linux/dns.go):
    // systemd-resolved via per-link split DNS, or a plain resolv.conf where one
    // prepended nameserver line covers glibc/dnscrypt-proxy/dnsmasq alike.
    const QFileInfo resolv(QStringLiteral("/etc/resolv.conf"));
    const auto real = resolv.canonicalFilePath();
    if (real.isEmpty()) {
        if (detail) *detail = QCoreApplication::translate("LinuxNetworkAvailability",
            "Cannot read /etc/resolv.conf; automatic routing has no supported DNS mechanism.");
        return DnsMechanism::Unavailable;
    }
    if (real.startsWith(QStringLiteral("/run/systemd/resolve/"))) return DnsMechanism::Resolved;
    QFile file(real);
    if (!file.open(QIODevice::ReadOnly)) {
        if (detail) *detail = QCoreApplication::translate("LinuxNetworkAvailability",
            "Cannot read /etc/resolv.conf; automatic routing has no supported DNS mechanism.");
        return DnsMechanism::Unavailable;
    }
    if (file.readAll().contains("nameserver 127.0.0.53")) return DnsMechanism::Resolved;
    if (!QFileInfo(real).isFile()) {
        if (detail) *detail = QCoreApplication::translate("LinuxNetworkAvailability",
            "/etc/resolv.conf is not a plain file; no supported DNS mechanism was found.");
        return DnsMechanism::Unavailable;
    }
    return DnsMechanism::PlainFile;
}

bool executableByPkexec(const QFileInfo &info)
{
    // pkexec refuses programs it does not own and rejects group/other-writable
    // ones; mirror that so the UI can explain the problem up front.
    return info.isFile() && info.isExecutable() && info.ownerId() == 0
        && !(info.permissions() & (QFile::WriteGroup | QFile::WriteOther));
}
}

QString linuxNetworkHelperExecutable()
{
    const QFileInfo installed{QLatin1String(JustConnectNetworkHelperPath)};
    if (executableByPkexec(installed)) return installed.absoluteFilePath();
    // Portable package layout: the helper travels in libexec/ next to the
    // application binary.
    const QFileInfo portable{QDir(QCoreApplication::applicationDirPath())
        .absoluteFilePath(QStringLiteral("../libexec/justconnect-network-helper"))};
    if (executableByPkexec(portable)) return portable.absoluteFilePath();
    return {};
}

LinuxHelperAvailability linuxNetworkHelperAvailability()
{
    LinuxHelperAvailability report;
    if (linuxNetworkHelperExecutable().isEmpty()) {
        const QFileInfo installed{QLatin1String(JustConnectNetworkHelperPath)};
        const QFileInfo portable{QDir(QCoreApplication::applicationDirPath())
            .absoluteFilePath(QStringLiteral("../libexec/justconnect-network-helper"))};
        const auto target = portable.exists() ? portable.absoluteFilePath() : installed.absoluteFilePath();
        report.helperDetail = QCoreApplication::translate("LinuxNetworkAvailability",
            "The JustConnect network helper is not installed as a root-owned executable at %1.")
            .arg(target);
        // Both routes from docs/build-linux.md, phrased as one copy-pasteable
        // command: portable packages fix the shipped copy in place, system
        // installs place it (plus the policy) at the annotated path.
        report.remedy = QCoreApplication::translate("LinuxNetworkAvailability",
            "Run: sudo chown root:root '%1' && sudo chmod 0755 '%1' — or install it to %2 "
            "as a root-owned executable, then reconnect.").arg(target, installed.absoluteFilePath());
        return report;
    }
    if (QStandardPaths::findExecutable(QStringLiteral("pkexec")).isEmpty()) {
        report.helperDetail = QCoreApplication::translate("LinuxNetworkAvailability",
            "polkit (pkexec) is not available; automatic routing needs it to request administrator privileges.");
        report.remedy = QCoreApplication::translate("LinuxNetworkAvailability",
            "Install polkit with your package manager (for example: sudo apt install policykit-1), then reconnect.");
        return report;
    }
    QString routingDetail;
    const auto mechanism = detectDnsMechanism(&routingDetail);
    if (mechanism == DnsMechanism::Unavailable) {
        report.routingDetail = routingDetail;
        return report;
    }
    report.available = true;
    return report;
}
