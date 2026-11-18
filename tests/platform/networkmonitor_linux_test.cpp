#include "infrastructure/networkaccess/linux/networkmonitor.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QTimer>
#include <iostream>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

// The monitor's test seam is a connected datagram socket that stands in for the
// netlink route socket, so the coalescing behavior is verifiable without any
// kernel network activity.
namespace {
void check(bool okay, const char *message) { if (!okay) throw std::runtime_error(message); }

void pump(QEventLoop &loop, int milliseconds)
{
    QTimer::singleShot(milliseconds, &loop, &QEventLoop::quit);
    loop.exec();
}
}

int main(int argc, char **argv) try {
    QCoreApplication app(argc, argv);
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) throw std::runtime_error("socketpair failed");

    LinuxNetworkMonitor monitor(fds[0]);
    int changes = 0;
    QObject::connect(&monitor, &LinuxNetworkMonitor::networkChanged, [&] { ++changes; });
    {
        QEventLoop loop;
        pump(loop, 600);
        check(changes == 0, "Idle monitor requested a network refresh");
    }
    {
        QEventLoop loop;
        // A burst of kernel events (like a DHCP renew writing several netlink
        // messages at once) must coalesce into exactly one refresh request.
        for (int index = 0; index < 8; ++index) {
            if (::write(fds[1], "x", 1) != 1) throw std::runtime_error("event write failed");
        }
        pump(loop, 700);
        check(changes == 1, "Event burst did not coalesce into one refresh request");
    }
    {
        QEventLoop loop;
        // A second burst after the first report must produce another report.
        for (int index = 0; index < 3; ++index) {
            if (::write(fds[1], "y", 1) != 1) throw std::runtime_error("event write failed");
        }
        pump(loop, 700);
        check(changes == 2, "Second event burst was not reported");
    }
    ::close(fds[1]);
    std::cout << "networkmonitor_linux_test passed" << std::endl;
    return 0;
} catch (const std::exception &error) {
    std::cerr << "FAILED: " << error.what() << std::endl;
    return 1;
}
