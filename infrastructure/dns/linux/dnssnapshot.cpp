#include "infrastructure/dns/linux/dnssnapshot.h"
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <optional>

namespace {
constexpr int MaxNameservers = 64, MaxSearchDomains = 64, MaxTokenBytes = 255;

struct ResolvConf { QStringList nameservers, search; QString domain; };

std::optional<ResolvConf> parseResolvConf(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return std::nullopt;
    ResolvConf parsed;
    for (auto line : QString::fromUtf8(file.readAll()).split('\n')) {
        int cut = line.indexOf('#');
        const int semicolon = line.indexOf(';');
        if (semicolon >= 0 && (cut < 0 || semicolon < cut)) cut = semicolon;
        if (cut >= 0) line.truncate(cut);
        const auto tokens = line.simplified().split(' ', Qt::SkipEmptyParts);
        if (tokens.isEmpty()) continue;
        auto append = [](QStringList &values, const QString &value) {
            if (values.contains(value)) return true;
            if (values.size() >= MaxSearchDomains || value.size() > MaxTokenBytes || value.contains(QChar(0))) return false;
            values.append(value);
            return true;
        };
        if (tokens.first() == QStringLiteral("nameserver")) {
            for (int i = 1; i < tokens.size(); ++i)
                if (!append(parsed.nameservers, tokens[i])) return std::nullopt;
        } else if (tokens.first() == QStringLiteral("search")) {
            for (int i = 1; i < tokens.size(); ++i)
                if (!append(parsed.search, tokens[i])) return std::nullopt;
        } else if (tokens.first() == QStringLiteral("domain") && tokens.size() >= 2) {
            parsed.domain = tokens[1];
        }
    }
    return parsed;
}
}

DnsSnapshot readLinuxDnsSnapshot()
{
    using Status = PlatformOperationResult::Status;
    const auto configuration = parseResolvConf(QStringLiteral("/etc/resolv.conf"));
    if (!configuration) return {{Status::Failed, "Cannot read /etc/resolv.conf"}, {}};
    auto nameservers = configuration->nameservers;
    // The systemd-resolved stub listener forwards to real upstreams; snapshot those instead.
    if (nameservers.contains(QStringLiteral("127.0.0.53"))) {
        const auto upstreams = parseResolvConf(QStringLiteral("/run/systemd/resolve/resolv.conf"));
        if (upstreams && !upstreams->nameservers.isEmpty()) nameservers = upstreams->nameservers;
    }
    QJsonObject resolvConf{{"nameservers", QJsonArray::fromStringList(nameservers)},
        {"search", QJsonArray::fromStringList(configuration->search)}};
    if (!configuration->domain.isEmpty()) resolvConf["domain"] = configuration->domain;
    const QJsonObject data{{"resolv_conf", resolvConf}};
    if (QJsonDocument(data).toJson(QJsonDocument::Compact).size() > LinuxDnsSnapshotBytes)
        return {{Status::Failed, "System resolver snapshot too large"}, {}};
    return {{}, data};
}
