#include "infrastructure/networkhelper/linux/networkownership.h"
#include "infrastructure/networkaddress/ipv4.h"

NetworkPolicySession::OriginalViewFilter linuxOriginalNetworkView(const LinuxHelperConfiguration &configuration,
    const LinuxHelperDevice &device, const QString &dnsMode)
{
    if (!canonicalUnicastIpv4(configuration.address) || !canonicalUnicastIpv4(configuration.peer)
        || device.name.isEmpty() || device.name.size() > 15 || device.index <= 0) return {};
    if (!dnsMode.isEmpty() && dnsMode != QLatin1String("resolved") && dnsMode != QLatin1String("file")) return {};
    return [configuration, device, dnsMode](const QJsonObject &network, const QJsonObject &dns, QString *reason)
        -> std::optional<NetworkPolicySession::OriginalView> {
        const auto fail = [reason](const QString &detail) {
            if (reason) *reason = detail;
            return std::nullopt;
        };
        if (!network["interfaces"].isArray() || !network["routes"].isArray())
            return fail(QStringLiteral("the network snapshot lacks interfaces or routes arrays"));
        // Subtract the owned nonpersistent TUN device as a whole: nothing else
        // can hold addresses on it, and the kernel keeps interface names
        // unique, so a matching name and index pair identifies this session's
        // device. Its administrative up flag may flap while a desktop network
        // manager adopts and releases the foreign device; packet I/O rides the
        // borrowed descriptor, so a momentary down state does not change the
        // original network this view must describe. A destroyed device (its
        // row gone) still fails closed, because the capture cannot survive it.
        QJsonArray interfaces;
        bool found = false;
        for (const auto &value : network["interfaces"].toArray()) {
            const auto row = value.toObject();
            if (row["name"].toString() == device.name && row["index"].toInt() == device.index) {
                if (found)
                    return fail(QStringLiteral("the owned tunnel device %1 is duplicated in the network snapshot").arg(device.name));
                found = true;
                continue;
            }
            interfaces.append(value);
        }
        if (!found)
            return fail(QStringLiteral("the owned tunnel device %1 is missing from the network snapshot").arg(device.name));
        // Subtract every route row that points at the owned interface.
        QJsonArray routes;
        for (const auto &value : network["routes"].toArray()) {
            if (value.toObject()["interface_index"].toInt() == device.index) continue;
            routes.append(value);
        }
        auto original = network;
        original["interfaces"] = interfaces;
        original["routes"] = routes;
        auto originalDns = dns;
        if (dnsMode == QLatin1String("file")) {
            // The helper prepended exactly one nameserver line; withdraw the
            // peer from the observed view. It must still lead the list for
            // campus names to win.
            const auto resolvConf = dns["resolv_conf"].toObject();
            if (!resolvConf["nameservers"].isArray())
                return fail(QStringLiteral("the resolv_conf snapshot lost its nameserver list"));
            QJsonArray nameservers;
            bool owned = false;
            for (const auto &value : resolvConf["nameservers"].toArray()) {
                if (value.toString() == configuration.peer) {
                    owned = true;
                    continue;
                }
                nameservers.append(value);
            }
            if (!owned)
                return fail(QStringLiteral("the owned nameserver is missing from resolv_conf"));
            auto updated = resolvConf;
            updated["nameservers"] = nameservers;
            originalDns["resolv_conf"] = updated;
        }
        // "resolved" keeps per-link settings outside the resolv.conf snapshot;
        // an empty mode means this session owns no DNS at all.
        return NetworkPolicySession::OriginalView{original, originalDns};
    };
}

bool linuxOriginalDnsMatches(const LinuxHelperConfiguration &configuration, const QString &dnsMode,
    const QJsonObject &dns)
{
    if (dnsMode.isEmpty() || dnsMode == QLatin1String("resolved")) return true;
    if (dnsMode != QLatin1String("file")) return false;
    const auto resolvConf = dns["resolv_conf"].toObject();
    if (!resolvConf["nameservers"].isArray()) return false;
    // The inserted peer must still be the first nameserver.
    return resolvConf["nameservers"].toArray().at(0).toString() == configuration.peer;
}
