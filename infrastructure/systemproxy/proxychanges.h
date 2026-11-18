#pragma once
#include <QObject>
#include <functional>
#include <memory>

class ProxyChanges final : public QObject
{
    Q_OBJECT
public:
    explicit ProxyChanges(QObject *parent = nullptr);
    ~ProxyChanges() override;
#ifdef Q_OS_LINUX
    // Linux-only test seams: the CI image has no dconf session, so tests inject
    // a snapshot reader and drive notifications directly.
    void setSnapshotReader(std::function<QByteArray()> reader);
    void handleSignal();
#endif
signals:
    void changed();
private:
    struct Watch;
    std::unique_ptr<Watch> watch;
};
