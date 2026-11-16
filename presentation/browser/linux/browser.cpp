#include "presentation/browser/origin.h"
#include "presentation/browser/signinbrowser.h"

#include <QFocusEvent>
#include <QHostAddress>
#include <QKeyEvent>
#include <QLoggingCategory>
#include <QPointer>
#include <QResizeEvent>
#include <QScopeGuard>
#include <QSslCertificate>
#include <QTimer>
#include <QtEndian>
#include <QWebEngineCertificateError>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebEngineSettings>
#include <QWebEngineUrlRequestInfo>
#include <QWebEngineUrlRequestInterceptor>
#include <QWebEngineView>
#include <optional>
#include <utility>

#if defined(JC_BROWSER_OPENSSL)
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

namespace {
Q_LOGGING_CATEGORY(browserLog,"justconnect.signin",QtWarningMsg)

#if defined(JC_BROWSER_OPENSSL)
X509 *parseCertificate(const QByteArray &der)
{
    const auto *data = reinterpret_cast<const unsigned char *>(der.constData());
    return d2i_X509(nullptr, &data, long(der.size()));
}

// Verify the presented chain against the configured campus CA anchors and host name.
// Without this build option the custom-CA path fails closed; pages the system already trusts need no anchor.
bool trusted(const QList<QSslCertificate> &chain, const QString &host, const QString &caPem)
{
    if (caPem.isEmpty() || chain.isEmpty() || host.isEmpty()) return false;
    const auto leafDer = chain.first().toDer();
    X509 *leaf = parseCertificate(leafDer);
    if (!leaf) return false;
    const auto freeLeaf = qScopeGuard([&] { X509_free(leaf); });
    X509_STORE *store = X509_STORE_new();
    STACK_OF(X509) *untrusted = sk_X509_new_null();
    X509_STORE_CTX *context = X509_STORE_CTX_new();
    const auto release = qScopeGuard([&] {
        X509_STORE_CTX_free(context); sk_X509_pop_free(untrusted, X509_free);
        X509_STORE_free(store); ERR_clear_error();
    });
    if (!store || !untrusted || !context) return false;
    for (const auto &anchor : QSslCertificate::fromData(caPem.toUtf8(), QSsl::Pem)) {
        X509 *parsed = parseCertificate(anchor.toDer());
        if (!parsed) return false;
        X509_STORE_add_cert(store, parsed);
        X509_free(parsed);
    }
    for (const auto &intermediate : chain.mid(1)) {
        X509 *parsed = parseCertificate(intermediate.toDer());
        if (!parsed) return false;
        sk_X509_push(untrusted, parsed);
    }
    X509_STORE_CTX_init(context, store, leaf, untrusted);
    const auto parameter = X509_STORE_CTX_get0_param(context);
    if (X509_VERIFY_PARAM_set_purpose(parameter, X509_PURPOSE_SSL_SERVER) != 1) return false;
    // Campus gateways are reached by address, so an IP host must match the iPAddress SAN
    // instead of OpenSSL's dNSName-only host comparison.
    const QHostAddress address(host);
    if (address.protocol() == QAbstractSocket::IPv4Protocol) {
        const auto raw = qToBigEndian(address.toIPv4Address());
        if (X509_VERIFY_PARAM_set1_ip(parameter, reinterpret_cast<const unsigned char *>(&raw), sizeof(raw)) != 1) return false;
    } else if (address.protocol() == QAbstractSocket::IPv6Protocol) {
        const auto bytes = address.toIPv6Address();
        if (X509_VERIFY_PARAM_set1_ip(parameter, bytes.c, sizeof(bytes.c)) != 1) return false;
    } else {
        const auto utf8Host = host.toUtf8();
        if (X509_VERIFY_PARAM_set1_host(parameter, utf8Host.constData(), 0) != 1) return false;
    }
    return X509_verify_cert(context) == 1;
}
#else
bool trusted(const QList<QSslCertificate> &, const QString &, const QString &)
{
    return false;
}
#endif
} // namespace

namespace {
// The page owns the navigation boundary: main-frame decisions come from the trust policy,
// rejected main frames report a failed load, and setHtml's internal load bypasses the policy.
class SignInPage final : public QWebEnginePage
{
public:
    SignInPage(QWebEngineProfile *profile, QObject *parent) : QWebEnginePage(profile, parent) {}
    std::function<bool(const QUrl &, bool)> navigation;
    bool htmlPending = false;
protected:
    // Chromium forwards page console output to the Qt log by default (Qt 6.12); identity
    // provider console messages must never enter application logs.
    void javaScriptConsoleMessage(JavaScriptConsoleMessageLevel, const QString &, int, const QString &) override {}
    bool acceptNavigationRequest(const QUrl &url, NavigationType, bool isMainFrame) override
    {
        if (isMainFrame && htmlPending) { htmlPending = false; return true; }
        return navigation ? navigation(url, isMainFrame) : false;
    }
};

// Mirrors the WebView2 resource filter on Windows. QtWebEngine can only refuse a request, not
// synthesize a response, and the interceptor runs on the IO thread: it reads captured policy
// copies and never touches widgets.
class SignInFilter final : public QWebEngineUrlRequestInterceptor
{
public:
    SignInFilter(QUrl callback, TlsOptions policy, QObject *parent)
        : QWebEngineUrlRequestInterceptor(parent), callback(std::move(callback)), policy(std::move(policy)) {}
    void interceptRequest(QWebEngineUrlRequestInfo &info) override
    {
        const QUrl target = info.requestUrl();
        // Main-frame callbacks complete through the navigation policy; every other context must
        // never reach the identity provider's ticket endpoint.
        if (info.resourceType() != QWebEngineUrlRequestInfo::ResourceTypeMainFrame
            && BrowserOrigin::sameEndpoint(target, callback)) { info.block(true); return; }
        // An explicit gateway TLS bypass never extends past the configured origin.
        if (!policy.verify && BrowserOrigin::escapesCertificateScope(target, callback)) info.block(true);
    }
private:
    const QUrl callback;
    const TlsOptions policy;
};
} // namespace

struct SignInBrowser::Native {
    // One off-the-record profile per window: no disk storage and no cookie sharing between dialogs.
    QWebEngineProfile profile;
    QWebEngineView *view = nullptr;
    SignInPage *page = nullptr;
    QUrl current, pending;
    QString html;
    bool htmlPending = false, failed = false;
};

SignInBrowser::SignInBrowser(QWidget *parent, const QUrl &callbackUrl, const TlsOptions &tls, NavigationPolicy navigation)
    : QWidget(parent), native(std::make_unique<Native>())
{
    setFocusPolicy(Qt::StrongFocus); setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    qCDebug(browserLog) << "profile start";
    native->view = new QWebEngineView(this);
    native->page = new SignInPage(&native->profile, native->view);
    native->view->setPage(native->page);
    // Owned by the profile's lifetime; Chromium drives it from the IO thread.
    native->profile.setUrlRequestInterceptor(new SignInFilter(callbackUrl, tls, &native->profile));
    const QPointer<SignInBrowser> self(this);
    native->page->navigation = [self, navigation](const QUrl &target, bool main) {
        const bool allowed = self && navigation(target, main);
        // QtWebEngine itself emits no completion for a blocked navigation, so report it here.
        if (!allowed && main && self) {
            qCDebug(browserLog) << "navigation rejected" << main;
            QTimer::singleShot(0, self.data(), [self] { if (self) emit self->loadFinished(false); });
        }
        return allowed;
    };
    connect(native->page, &QWebEnginePage::loadStarted, this, [this] { emit loadStarted(); });
    connect(native->page, &QWebEnginePage::loadFinished, this, [this](bool okay) {
        if (native->page) native->page->htmlPending = false;
        emit loadFinished(okay);
    });
    connect(native->page, &QWebEnginePage::urlChanged, this, [this](const QUrl &url) {
        native->current = url; emit urlChanged(url);
    });
    connect(native->page, &QWebEnginePage::certificateError, this,
        [self, callbackUrl, tls](QWebEngineCertificateError error) {
            if (!self) { error.rejectCertificate(); return; }
            const QUrl target = error.url();
            const bool same = BrowserOrigin::same(target, callbackUrl);
            // Chromium re-evaluates every request's certificate, so an exception never outlives its request.
            const bool okay = error.isOverridable()
                && ((!tls.verify && same) || (tls.verify && trusted(error.certificateChain(), target.host(), tls.caPem)));
            qCDebug(browserLog) << "certificate error" << target << int(error.type());
            if (okay) { error.acceptCertificate(); return; }
            error.rejectCertificate();
            emit self->certificateRejected();
        });
    connect(native->page, &QWebEnginePage::renderProcessTerminated, this,
        [self](QWebEnginePage::RenderProcessTerminationStatus) {
            if (!self || self->native->failed) return;
            self->native->failed = true;
            emit self->initializationFailed();
            emit self->loadFinished(false);
        });
    installKeyboardFilter();
}

SignInBrowser::~SignInBrowser()
{
    blockSignals(true);
    // The view owns the page and both must end before the off-the-record profile goes away.
    delete native->view;
    native->view = nullptr;
    native->page = nullptr;
}

bool SignInBrowser::eventFilter(QObject *watched, QEvent *event)
{
    Q_UNUSED(watched);
    if (event->type() == QEvent::KeyPress) {
        const auto *key = static_cast<QKeyEvent *>(event);
        const int modifiers = int(key->modifiers() & (Qt::ShiftModifier | Qt::ControlModifier | Qt::AltModifier | Qt::MetaModifier));
        if (key->key() == Qt::Key_L && modifiers == int(Qt::ControlModifier)) {
            emit addressFocusRequested();
            return true;
        }
    }
    return QWidget::eventFilter(watched, event);
}

void SignInBrowser::installKeyboardFilter()
{
    // QtWebEngine delivers web-content keys to its internal delegate; that proxy can be re-created
    // lazily, so reattach on every show and focus change.
    if (!native->view) return;
    native->view->removeEventFilter(this);
    native->view->installEventFilter(this);
    if (QWidget *proxy = native->view->focusProxy()) {
        proxy->removeEventFilter(this);
        proxy->installEventFilter(this);
    }
}

void SignInBrowser::load(const QUrl &target)
{
    qCDebug(browserLog) << "load requested" << target.isEmpty();
    native->pending = target; native->htmlPending = false;
    if (native->failed) { QTimer::singleShot(0, this, [this] { emit initializationFailed(); emit loadFinished(false); }); return; }
    if (native->view && !target.isEmpty()) native->view->load(target);
}

QUrl SignInBrowser::url() const { return native->current; }
void SignInBrowser::back() { if (native->view) native->view->back(); }
void SignInBrowser::forward() { if (native->view) native->view->forward(); }
void SignInBrowser::reload() { if (native->view) native->view->reload(); }

void SignInBrowser::setHtml(const QString &html)
{
    qCDebug(browserLog) << "html requested" << bool(native->page);
    native->html = html; native->htmlPending = true;
    if (native->failed) { QTimer::singleShot(0, this, [this] { emit initializationFailed(); emit loadFinished(false); }); return; }
    if (native->page) {
        native->page->htmlPending = true;
        native->page->setHtml(html);
    }
}

void SignInBrowser::runJavaScript(const QString &script, std::function<void(const QVariant &)> result)
{
    if (!native->page) { result({}); return; }
    native->page->runJavaScript(script, std::move(result));
}

void SignInBrowser::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    if (native->view) native->view->setGeometry(rect());
}

void SignInBrowser::showEvent(QShowEvent *event)
{
    QWidget::showEvent(event);
    if (native->view) native->view->show();
    installKeyboardFilter();
}

void SignInBrowser::hideEvent(QHideEvent *event)
{
    QWidget::hideEvent(event);
    if (native->view) native->view->hide();
}

void SignInBrowser::focusInEvent(QFocusEvent *event)
{
    QWidget::focusInEvent(event);
    if (native->view) native->view->setFocus();
    installKeyboardFilter();
}
