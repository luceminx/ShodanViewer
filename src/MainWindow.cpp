
#include "MainWindow.h"
#include "ShodanClient.h"
#include "HostTableModel.h"
#include "CacheStore.h"
#include "JsonDialog.h"
#include "QueryTab.h"
#include "SearchBarWidgets.h"
#include "Proxy.h"
#include "version.h"

#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QTableView>
#include <QTabWidget>
#include <QTabBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidget>
#include <QHeaderView>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QInputDialog>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QTextStream>
#include <QStandardPaths>
#include <QDir>
#include <QClipboard>
#include <QApplication>
#include <QItemSelectionModel>
#include <QPainter>
#include <QPaintEvent>
#include <QFont>
#include <QPen>
#include <QColor>
#include <QRectF>
#include <QPalette>
#include <QAbstractItemView>
#include <QMouseEvent>
#include <QObject>
#include <functional>
#include <QToolButton>
#include <QShortcut>
#include <QKeySequence>
#include <QKeyEvent>
#include <QFontMetrics>
#include <QStringList>
#include <QEvent>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QStyle>
#include <QMovie>
#include <QGridLayout>
#include <QCompleter>
#include <QStringListModel>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <cstring> 
#include <QNetworkProxy>
#include <QProgressDialog>
#include <QEventLoop>
#include <QTimer>
#include <QElapsedTimer>
#include <optional>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QRadioButton>


namespace {

    // ------------------------------------------------------------
    // 16 进制证书序列号 → 10 进制字符串
    // 序列号最长 20 字节（160 位），超出 qulonglong 范围，
    // 用十进制字符串逐位做 *16 + v 的大数运算。
    // 输入允许 0x 前缀 / 冒号 / 空格（浏览器、Windows 证书查看器的格式）；
    // 纯数字输入视为已经是 10 进制，原样返回；非法字符返回空串。
    // ------------------------------------------------------------
    QString hexSerialToDecimal(QString hex)
    {
        hex.remove(QLatin1Char(':'));
        hex.remove(QLatin1Char(' '));
        hex.remove(QLatin1Char('-'));
        hex = hex.trimmed();
        if (hex.startsWith("0x", Qt::CaseInsensitive))
            hex.remove(0, 2);
        if (hex.isEmpty())
            return {};

        bool allDigits = true;
        for (const QChar& ch : hex)
            if (!ch.isDigit()) { allDigits = false; break; }
        if (allDigits)
            return hex;                       // 已是 10 进制

        QString dec = QStringLiteral("0");
        for (const QChar& ch : hex) {
            int v = -1;
            if (ch.isDigit()) {
                v = ch.digitValue();
            }
            else {
                const char c = ch.toLower().toLatin1();
                if (c >= 'a' && c <= 'f')
                    v = c - 'a' + 10;
            }
            if (v < 0)
                return {};                    // 非法字符

            long long carry = v;
            for (int i = dec.size() - 1; i >= 0; --i) {
                const long long d = dec.at(i).digitValue() * 16 + carry;
                dec[i] = QChar(QLatin1Char(char('0' + d % 10)));
                carry = d / 10;
            }
            while (carry > 0) {
                dec.prepend(QChar(QLatin1Char(char('0' + carry % 10))));
                carry /= 10;
            }
        }
        while (dec.size() > 1 && dec.startsWith(QLatin1Char('0')))
            dec.remove(0, 1);
        return dec;
    }

    // ------------------------------------------------------------
    // MurmurHash3 x86 32bit（seed = 0），与 Python mmh3.hash 一致
    // ------------------------------------------------------------
    quint32 murmur3_32(const QByteArray& data, quint32 seed = 0)
    {
        const auto rotl = [](quint32 x, int r) -> quint32 {
            return (x << r) | (x >> (32 - r));
            };
        const quint32 c1 = 0xcc9e2d51u;
        const quint32 c2 = 0x1b873593u;

        const int nBlocks = data.size() / 4;
        quint32 h1 = seed;
        const char* p = data.constData();

        for (int i = 0; i < nBlocks; ++i) {
            quint32 k1;
            memcpy(&k1, p + i * 4, 4);        // 小端读取
            k1 *= c1; k1 = rotl(k1, 15); k1 *= c2;
            h1 ^= k1; h1 = rotl(h1, 13); h1 = h1 * 5u + 0xe6546b64u;
        }

        const unsigned char* tail =
            reinterpret_cast<const unsigned char*>(p + nBlocks * 4);
        quint32 k1 = 0;
        switch (data.size() & 3) {
        case 3: k1 ^= quint32(tail[2]) << 16; [[fallthrough]];
        case 2: k1 ^= quint32(tail[1]) << 8; [[fallthrough]];
        case 1: k1 ^= quint32(tail[0]);
            k1 *= c1; k1 = rotl(k1, 15); k1 *= c2; h1 ^= k1;
        }

        h1 ^= quint32(data.size());
        h1 ^= h1 >> 16; h1 *= 0x85ebca6bu;
        h1 ^= h1 >> 13; h1 *= 0xc2b2ae35u;
        h1 ^= h1 >> 16;
        return h1;
    }

    // ------------------------------------------------------------
    // 复刻 Python codecs.encode(raw, "base64") 的输出：
    // 标准 base64 后每 76 字符插入 \n，末尾固定追加 \n。
    // Shodan / Fofa 的 favicon hash 都是对这个字节串做 mmh3，
    // 换行符必须原样参与哈希，否则结果对不上。
    // ------------------------------------------------------------
    QByteArray faviconHashSource(const QByteArray& raw)
    {
        const QByteArray b64 = raw.toBase64();
        QByteArray out;
        out.reserve(b64.size() + b64.size() / 76 + 2);
        for (int i = 0; i < b64.size(); i += 76) {
            out += b64.mid(i, 76);
            out += '\n';
        }
        return out;
    }

    // 导出补抓缺页时的 API 限速间隔（低档套餐约 1 次/秒）
    constexpr int kExportApiIntervalMs = 1000;

    // 离开作用域自动复位布尔标志
    struct BoolGuard {
        bool& f;
        ~BoolGuard() { f = false; }
    };

    // ------------------------------------------------------------
    // 同步取一页搜索结果：事件循环等待 ShodanClient 信号。
    // 失败 / 超时（30s 兜底）返回空 optional。
    // 仅供导出补抓缺失页使用；结果只进导出文件，不写 SQLite。
    // ------------------------------------------------------------
    std::optional<QJsonObject> fetchPageBlocking(
        ShodanClient* client, const QString& query, int page)
    {
        QEventLoop loop;
        std::optional<QJsonObject> result;
        bool failed = false;

        const auto okConn = QObject::connect(
            client, &ShodanClient::searchReady, &loop,
            [&](const QString& q, int p, const QJsonObject& o) {
                if (q != query || p != page) return;
                result = o;
                loop.quit();
            });

        const auto errConn = QObject::connect(
            client, &ShodanClient::searchError, &loop,
            [&](const QString& q, int p, const QString&) {
                if (q != query || p != page) return;
                failed = true;
                loop.quit();
            });

        QTimer::singleShot(30000, &loop, &QEventLoop::quit);

        client->search(query, page);
        loop.exec();

        QObject::disconnect(okConn);
        QObject::disconnect(errConn);

        if (failed) return std::nullopt;
        return result;
    }


    // 嵌套路径取值："ssl.cert.subject.cn"
    QJsonValue lookup(const QJsonObject& obj, const QString& path)
    {
        QJsonValue v = obj;
        for (const QString& p : path.split('.')) {
            if (!v.isObject()) return {};
            v = v.toObject().value(p);
        }
        return v;
    }

    // 字符串数组 → "a;b;c"
    QString joinArray(const QJsonValue& v)
    {
        QStringList items;
        for (const auto& x : v.toArray())
            items << x.toString();
        return items.join(';');
    }

    // 对象键名 → "CVE-xxx;CVE-yyy"（vulns 用）
    QString joinKeys(const QJsonValue& v)
    {
        return v.isObject()
            ? QStringList(v.toObject().keys()).join(';')
            : QString();
    }

    // ------------------------------------------------------------
    // http/https 服务 → 可直接访问的 URL
    // 主机名优先级：hostnames > 证书CN > http.host(非IP时) > ip_str
    // 说明：http.host 是 Shodan 发出的 Host 头，扫描时通常就是 IP，
    //       所以必须放最后并过滤；证书 CN 可能为 *.example.com，需去前缀
    // ------------------------------------------------------------
    QString buildHttpUrl(const QJsonObject& o)
    {
        const QString module = lookup(o, "_shodan.module").toString().toLower();
        const bool https = module.startsWith("https");
        const QString scheme = https ? "https" : "http";
        const QString ip = o.value("ip_str").toString();

        // 判断候选主机是否可用：非空、不等于本条记录的 IP
        auto usable = [&ip](const QString& h) {
            return !h.isEmpty() && h.compare(ip, Qt::CaseInsensitive) != 0;
            };

        QString host;

        // 1) hostnames：rDNS / 域名记录，最可靠的可访问主机名
        for (const auto& x : o.value("hostnames").toArray()) {
            const QString h = x.toString().trimmed();
            if (usable(h)) { host = h; break; }
        }

        // 2) 证书 CN：https 结果的高价值来源，去掉 *. 通配前缀
        if (host.isEmpty()) {
            QString cn = lookup(o, "ssl.cert.subject.cn").toString().trimmed();
            if (cn.startsWith("*.")) cn.remove(0, 2);
            if (usable(cn) && cn.contains('.'))
                host = cn;
        }

        // 3) http.host：仅当它不是 IP 时才有意义
        if (host.isEmpty()) {
            const QString hh = o.value("http").toObject().value("host").toString().trimmed();
            if (usable(hh))
                host = hh;
        }

        // 4) 都没有 → 只能用 IP
        if (host.isEmpty()) host = ip;

        const int port = o.value("port").toInt();
        const int defaultPort = https ? 443 : 80;

        QString url = scheme + "://" + host;
        if (port > 0 && port != defaultPort)
            url += ":" + QString::number(port);
        return url;
    }

} // namespace




// ============================================================
// MainWindow 构造函数
// ============================================================

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
    client_(new ShodanClient(this)),
    cache_(nullptr),
    settings_(QCoreApplication::applicationDirPath() + "/settings.ini",QSettings::IniFormat)
{
    // SQLite 缓存目录
    const QString dir = QCoreApplication::applicationDirPath();

    cache_ = new CacheStore(dir + "/cache.sqlite");

    // 连接代理
    applyProxy(loadProxyConfig());

    // 恢复 API Key
    client_->setApiKey(
        settings_.value("api/key").toString()
    );

    faviconNam_ = new QNetworkAccessManager(this);
    configureUi();
    configureMenus();

    // --------------------------------------------------------
    // API 账户信息
    // --------------------------------------------------------

    connect(
        client_,
        &ShodanClient::apiInfoReady,
        this,
        [this](const QJsonObject& o) {
            accountLabel_->setAccountInfo(o);
        }
    );

    // --------------------------------------------------------
    // 查询数量返回
    // --------------------------------------------------------

    connect(
        client_,
        &ShodanClient::countReady,
        this,
        [this](const QString& query, const QJsonObject& o) {

            const int total = o.value("total").toInt();

            // 更新所有相同查询语句的标签页
            for (int i = 0; i < tabs_->count(); ++i) {

                auto* tab =
                    dynamic_cast<QueryTab*>(tabs_->widget(i));

                if (!tab || tab->query != query)
                    continue;

                tab->totalResults = total;

                tab->updateNavigation();

                tab->statusLabel->setText(
                    QString("共 %1 条结果").arg(total)
                );
            }
        }
    );

    // --------------------------------------------------------
    // 搜索结果返回
    // --------------------------------------------------------

    connect(
        client_,
        &ShodanClient::searchReady,
        this,
        [this](
            const QString& query,
            int page,
            const QJsonObject& o
            ) {
                if (exportingFetch_) {
                    client_->getApiInfo();
                    return;
                }

                // 保存搜索结果到 SQLite
                cache_->putPage(query, page, o);

                // 搜索 API 成功后刷新账户 Credits
                client_->getApiInfo();

                // 将结果更新到对应查询标签页
                for (int i = 0; i < tabs_->count(); ++i) {

                    auto* tab =
                        dynamic_cast<QueryTab*>(tabs_->widget(i));

                    if (!tab)
                        continue;

                    if (tab->query != query ||
                        tab->currentPage != page)
                        continue;

                    displayPage(tab, o);
                }
        }
    );

    // --------------------------------------------------------
    // API 请求错误
    // --------------------------------------------------------

    connect(
        client_,
        &ShodanClient::requestError,
        this,
        [this](const QString& e) {
            if (exportingFetch_) return;
            QMessageBox::warning(this, "Shodan API", e);
        }
    );

    // 如果已经配置 API Key，自动获取账户信息
    if (!client_->apiKey().isEmpty()) {
        client_->getApiInfo();
    }

    resize(1250, 760);

    setWindowTitle(QString("ShodanViewer %1").arg(SHODAN_VIEWER_VERSION));
}


// ============================================================
// MainWindow 析构函数
// ============================================================

MainWindow::~MainWindow()
{
    delete cache_;
}


// ============================================================
// 初始化主界面
// ============================================================

void MainWindow::configureUi()
{
    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);

    root->setContentsMargins(6, 6, 6, 4);
    root->setSpacing(4);

    // --------------------------------------------------------
    // 顶部查询栏
    // --------------------------------------------------------

    auto* bar = new QHBoxLayout;

    auto* caption = new QLabel("查询条件");

    queryEdit_ = new InlineCompleter;

    //queryEdit_->setPlaceholderText(
    //    "例如：apache  或  port:443 country:SG"
    //);


    searchButton_ = new QPushButton("查询");

    accountLabel_ = new CreditIndicator;

    bar->addWidget(caption);
    bar->addWidget(queryEdit_, 1);
    bar->addWidget(searchButton_);
    bar->addWidget(accountLabel_);

    root->addLayout(bar);

    // --------------------------------------------------------
    // 标签页
    // --------------------------------------------------------

    tabs_ = new QTabWidget;

    tabs_->setTabsClosable(true);

    // 固定标签页位置，保证首页始终位于第一个位置
    tabs_->setMovable(false);

    tabs_->setDocumentMode(true);

    root->addWidget(tabs_, 1);

    setCentralWidget(central);

    new TableBlankClickFilter(
        [this]() -> QTableView* {
            if (auto* tab = currentQueryTab())
                return tab->table;
            return nullptr;
        },
        this);
    // 创建首页
    createHomeTab();

    // --------------------------------------------------------
    // 查询按钮
    // --------------------------------------------------------

    connect(
        searchButton_,
        &QPushButton::clicked,
        this,
        &MainWindow::search
    );

    connect(
        queryEdit_,
        &QLineEdit::returnPressed,
        this,
        &MainWindow::search
    );

    // --------------------------------------------------------
    // 关闭标签页
    // --------------------------------------------------------

    connect(
        tabs_,
        &QTabWidget::tabCloseRequested,
        this,
        [this](int index) {

            // 首页固定存在，不允许关闭
            if (index == 0)
                return;

            QWidget* widget = tabs_->widget(index);

            tabs_->removeTab(index);

            widget->deleteLater();
        }
    );

    // --------------------------------------------------------
    // 切换标签页时同步顶部查询框
    // --------------------------------------------------------

    connect(
        tabs_,
        &QTabWidget::currentChanged,
        this,
        [this](int index) {

            auto* tab =
                dynamic_cast<QueryTab*>(tabs_->widget(index));

            if (tab) {
                queryEdit_->setText(tab->query);
            }
            else {
                queryEdit_->clear();
            }
        }
    );

    // 隐藏首页的关闭按钮
    auto* tabBar = tabs_->findChild<QTabBar*>();

    if (tabBar) {
        tabBar->setTabButton(
            0,
            QTabBar::RightSide,
            nullptr
        );

        tabBar->setTabButton(
            0,
            QTabBar::LeftSide,
            nullptr
        );
    }
}


// ============================================================
// 创建首页
// ============================================================

void MainWindow::createHomeTab()
{
    auto* home = new QWidget();

    // 使用 Qt Property 保存当前选中的分类
    home->setProperty("selectedCategory", "All");

    auto* rootLayout = new QVBoxLayout(home);
    rootLayout->setContentsMargins(20, 16, 20, 16);
    rootLayout->setSpacing(12);

    // =========================================================
    // 页面标题
    // =========================================================

    auto* titleLabel = new QLabel("Shodan语法参考");

    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(20);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);

    auto* descriptionLabel = new QLabel(
        "A reference guide to Shodan search filters. "
        "Use these filters to narrow down search results."
    );

    descriptionLabel->setWordWrap(true);
    descriptionLabel->setStyleSheet(
        "color: palette(mid);"
        "font-size: 13px;"
    );

    //rootLayout->addWidget(titleLabel);
    //rootLayout->addWidget(descriptionLabel);
    auto* headerRow = new QHBoxLayout;

    auto* headerLeft = new QVBoxLayout;
    headerLeft->addWidget(titleLabel);
    headerLeft->addWidget(descriptionLabel);
    headerRow->addLayout(headerLeft, 1);

    // —— 工具一：证书序列号 16 → 10 进制并查询 ——
    auto* serialRow = new QHBoxLayout;
    auto* serialLabel = new QLabel("计算证书序列号");
    auto* serialEdit = new QLineEdit;
    serialEdit->setPlaceholderText("请将16进制证书序列号粘贴到此处!");
    auto* serialButton = new QPushButton("计算并查询");
    serialRow->addWidget(serialLabel);
    serialRow->addWidget(serialEdit, 1);
    serialRow->addWidget(serialButton);

    // —— 工具二：favicon hash 计算并查询 ——
    auto* faviconRow = new QHBoxLayout;
    auto* faviconLabel = new QLabel("计算favicon hash");
    auto* faviconEdit = new QLineEdit;
    faviconEdit->setPlaceholderText("请将网站的Favicon的URL粘贴到此处!");
    auto* faviconButton = new QPushButton("计算并查询");
    faviconRow->addWidget(faviconLabel);
    faviconRow->addWidget(faviconEdit, 1);
    faviconRow->addWidget(faviconButton);

    auto* toolsColumn = new QVBoxLayout;
    toolsColumn->setSpacing(6);
    toolsColumn->addLayout(serialRow);
    toolsColumn->addLayout(faviconRow);
    headerRow->addLayout(toolsColumn, 0);

    const int kToolLabelWidth = 120;   // 覆盖较宽的“计算证书序列号”
    const int kToolEditMin = 340;   // 输入框最小长度，想要更长改这里
    serialEdit->setClearButtonEnabled(true);
    faviconEdit->setClearButtonEnabled(true);

    serialLabel->setFixedWidth(kToolLabelWidth);
    faviconLabel->setFixedWidth(kToolLabelWidth);
    serialEdit->setMinimumWidth(kToolEditMin);
    faviconEdit->setMinimumWidth(kToolEditMin);


    rootLayout->addLayout(headerRow);

    // =========================================================
    // 查询语法提示
    // =========================================================

    auto* syntaxLabel = new QLabel(
        "<b>搜索语法</b><br>"
        "①直接输入产品名或者特征字符<br>"
        "②使用过滤器，格式为：<code>filter:value</code>，多条件组合时，默认空格表示AND，逻辑或需显式使用OR<br>"
        "③排除则在过滤器前加 -<br><br>"
        "<code>apache city:London port:443 OR port:80 -http.status:404</code>"
    );

    syntaxLabel->setTextFormat(Qt::RichText);
    syntaxLabel->setWordWrap(true);
    syntaxLabel->setTextInteractionFlags(
        Qt::TextSelectableByMouse
    );

    syntaxLabel->setStyleSheet(
        "QLabel {"
        "  background-color: palette(alternate-base);"
        "  border: 1px solid palette(mid);"
        "  border-radius: 6px;"
        "  padding: 12px;"
        "}"
    );

    rootLayout->addWidget(syntaxLabel);

    // =========================================================
    // Filter Search
    // =========================================================

    auto* searchEdit = new QLineEdit();

    searchEdit->setPlaceholderText(
        "Search filters... (e.g. city, ssl, http.title)"
    );

    searchEdit->setClearButtonEnabled(true);
    searchEdit->setMinimumHeight(36);

    searchEdit->setStyleSheet(
        "QLineEdit {"
        "  border: 1px solid palette(mid);"
        "  border-radius: 6px;"
        "  padding: 6px 10px;"
        "  font-size: 13px;"
        "}"
        "QLineEdit:focus {"
        "  border: 1px solid palette(highlight);"
        "}"
    );

    rootLayout->addWidget(searchEdit);

    // =========================================================
    // 分类筛选按钮
    // =========================================================

    auto* categoryBar = new QHBoxLayout();
    categoryBar->setSpacing(6);

    QStringList categoryNames = {
        "All", "General", "Screenshots", "Cloud",
        "HTTP", "Bitcoin", "SNMP", "SSL",
        "NTP", "Telnet", "SSH", "Restricted"
    };

    QList<QToolButton*> categoryButtons;

    for (const QString& name : categoryNames)
    {
        auto* button = new QToolButton();

        button->setText(name);
        button->setCheckable(true);
        button->setAutoExclusive(true);
        button->setCursor(Qt::PointingHandCursor);

        if (name == "All")
            button->setChecked(true);

        categoryButtons.append(button);
        categoryBar->addWidget(button);
    }

    categoryBar->addStretch();

    rootLayout->addLayout(categoryBar);

    // =========================================================
    // 过滤器数据结构
    // =========================================================

    struct FilterInfo
    {
        QString name;
        QString description;
        QString example;
    };

    struct CategoryInfo
    {
        QString name;
        QString description;
        QList<FilterInfo> filters;
    };

    // =========================================================
    // 过滤器分类
    // =========================================================

    QList<CategoryInfo> categories = {

        {
            "General",
            "General-purpose filters for searching Shodan hosts.",
            {
                { "all", "Search across all available fields.", "all:apache" },
                { "asn", "Autonomous System Number.", "asn:AS15169" },
                { "asset", "Filter by asset information.", "asset:example.com" },
                { "city", "City where the host is located.", "city:London" },
                { "country", "Two-letter country code.", "country:GB" },
                { "cpe", "Common Platform Enumeration identifier.", "cpe:apache" },
                { "device", "Device type or category.", "device:router" },
                { "domain", "Domain associated with the host.", "domain:example.com" },
                { "geo", "Geographical coordinates.", "geo:51.5072,-0.1276" },
                { "google_ads", "Google Ads identifier.", "google_ads:123456" },
                { "google_analytics", "Google Analytics identifier.", "google_analytics:UA-123456" },
                { "google_tag_manager", "Google Tag Manager identifier.", "google_tag_manager:GTM-XXXX" },
                { "has_ipv6", "Whether the host has IPv6 information.", "has_ipv6:true" },
                { "has_screenshot", "Whether the host has a screenshot.", "has_screenshot:true" },
                { "has_ssl", "Whether the host supports SSL/TLS.", "has_ssl:true" },
                { "has_vuln", "Whether the host has known vulnerabilities.", "has_vuln:true" },
                { "hash", "Hash value of a service response.", "hash:123456789" },
                { "hostname", "Hostname associated with the host.", "hostname:example.com" },
                { "ip", "IP address of the host.", "ip:8.8.8.8" },
                { "isp", "Internet Service Provider.", "isp:Google" },
                { "link", "Link associated with the host.", "link:example.com" },
                { "meta_pixel", "Meta Pixel identifier.", "meta_pixel:123456" },
                { "net", "IP network range in CIDR notation.", "net:192.168.1.0/24" },
                { "org", "Organization associated with the IP.", "org:Google" },
                { "os", "Operating system detected on the host.", "os:Linux" },
                { "port", "Port number exposed by the host.", "port:443" },
                { "postal", "Postal or ZIP code.", "postal:10001" },
                { "product", "Software product detected by Shodan.", "product:Apache" },
                { "region", "Geographical region or state.", "region:California" },
                { "scan", "Scan information.", "scan:123456" },
                { "shodan.module", "Shodan scanner module.", "shodan.module:http" },
                { "state", "State or administrative area.", "state:California" },
                { "tiktok_pixel", "TikTok Pixel identifier.", "tiktok_pixel:123456" },
                { "version", "Version of detected software.", "version:2.4.54" },
                { "x_pixel", "X Pixel identifier.", "x_pixel:123456" }
            }
        },

        {
            "Screenshots",
            "Filters related to screenshots collected by Shodan.",
            {
                { "screenshot.hash", "Hash of the screenshot.", "screenshot.hash:123456" },
                { "screenshot.label", "Label associated with the screenshot.", "screenshot.label:login" }
            }
        },

        {
            "Cloud",
            "Filters for identifying cloud infrastructure.",
            {
                { "cloud.provider", "Cloud service provider.", "cloud.provider:Amazon" },
                { "cloud.region", "Cloud infrastructure region.", "cloud.region:us-east-1" },
                { "cloud.service", "Cloud service type.", "cloud.service:EC2" }
            }
        },

        {
            "HTTP",
            "Filters for HTTP services and web server information.",
            {
                { "http.component", "Web technology detected on the page.", "http.component:WordPress" },
                { "http.component_category", "Category of detected web technology.", "http.component_category:CMS" },
                { "http.dom_hash", "Hash of the document object model.", "http.dom_hash:123456" },
                { "http.favicon.hash", "Hash of the website favicon.", "http.favicon.hash:123456" },
                { "http.headers_hash", "Hash of HTTP response headers.", "http.headers_hash:123456" },
                { "http.html", "Search within the HTTP response HTML.", "http.html:login" },
                { "http.html_hash", "Hash of the HTTP response HTML.", "http.html_hash:123456" },
                { "http.robots_hash", "Hash of the robots.txt file.", "http.robots_hash:123456" },
                { "http.securitytxt", "Whether security.txt information exists.", "http.securitytxt:true" },
                { "http.server_hash", "Hash of the HTTP server information.", "http.server_hash:123456" },
                { "http.status", "HTTP response status code.", "http.status:200" },
                { "http.title", "Title of the HTTP page.", "http.title:Dashboard" },
                { "http.title_hash", "Hash of the HTTP page title.", "http.title_hash:123456" },
                { "http.waf", "Web Application Firewall detected.", "http.waf:Cloudflare" }
            }
        },

        {
            "Bitcoin",
            "Filters for Bitcoin-related services.",
            {
                { "bitcoin.ip", "Bitcoin node IP address.", "bitcoin.ip:8.8.8.8" },
                { "bitcoin.ip_count", "Number of Bitcoin IP addresses.", "bitcoin.ip_count:10" },
                { "bitcoin.port", "Bitcoin service port.", "bitcoin.port:8333" },
                { "bitcoin.version", "Bitcoin protocol version.", "bitcoin.version:70015" }
            }
        },

        {
            "SNMP",
            "Filters for Simple Network Management Protocol services.",
            {
                { "snmp.contact", "SNMP system contact information.", "snmp.contact:admin" },
                { "snmp.location", "SNMP system location.", "snmp.location:London" },
                { "snmp.name", "SNMP system name.", "snmp.name:router" }
            }
        },

        {
            "SSL",
            "Filters for SSL/TLS certificates and configurations.",
            {
                { "ssl", "Search for SSL/TLS services.", "ssl:true" },
                { "ssl.alpn", "Application-Layer Protocol Negotiation.", "ssl.alpn:h2" },
                { "ssl.cert.alg", "Certificate signature algorithm.", "ssl.cert.alg:sha256WithRSAEncryption" },
                { "ssl.cert.expired", "Whether the certificate has expired.", "ssl.cert.expired:true" },
                { "ssl.cert.extension", "Certificate extension information.", "ssl.cert.extension:subjectAltName" },
                { "ssl.cert.fingerprint", "Certificate fingerprint.", "ssl.cert.fingerprint:123456" },
                { "ssl.cert.issuer.cn", "Certificate issuer common name.", "ssl.cert.issuer.cn:Let's Encrypt" },
                { "ssl.cert.pubkey.bits", "Public key size in bits.", "ssl.cert.pubkey.bits:2048" },
                { "ssl.cert.pubkey.type", "Public key algorithm type.", "ssl.cert.pubkey.type:rsa" },
                { "ssl.cert.serial", "Certificate serial number.", "ssl.cert.serial:123456" },
                { "ssl.cert.subject.cn", "Certificate subject common name.", "ssl.cert.subject.cn:example.com" },
                { "ssl.chain_count", "Number of certificates in the chain.", "ssl.chain_count:2" },
                { "ssl.cipher.bits", "Cipher key strength in bits.", "ssl.cipher.bits:256" },
                { "ssl.cipher.name", "Name of the negotiated cipher.", "ssl.cipher.name:AES" },
                { "ssl.cipher.version", "SSL/TLS cipher protocol version.", "ssl.cipher.version:TLSv1.2" },
                { "ssl.ja3s", "JA3S TLS server fingerprint.", "ssl.ja3s:abc123" },
                { "ssl.jarm", "JARM TLS server fingerprint.", "ssl.jarm:abc123" },
                { "ssl.version", "SSL/TLS protocol version.", "ssl.version:TLSv1.2" }
            }
        },

        {
            "NTP",
            "Filters for Network Time Protocol services.",
            {
                { "ntp.ip", "NTP server IP address.", "ntp.ip:8.8.8.8" },
                { "ntp.ip_count", "Number of NTP IP addresses.", "ntp.ip_count:10" },
                { "ntp.more", "Additional NTP response information.", "ntp.more:true" },
                { "ntp.port", "NTP service port.", "ntp.port:123" }
            }
        },

        {
            "Telnet",
            "Filters for Telnet protocol negotiation options.",
            {
                { "telnet.do", "Telnet DO command.", "telnet.do:1" },
                { "telnet.dont", "Telnet DONT command.", "telnet.dont:1" },
                { "telnet.option", "Telnet option negotiation.", "telnet.option:1" },
                { "telnet.will", "Telnet WILL command.", "telnet.will:1" },
                { "telnet.wont", "Telnet WONT command.", "telnet.wont:1" }
            }
        },

        {
            "SSH",
            "Filters for Secure Shell services.",
            {
                { "ssh.hassh", "HASSH fingerprint of an SSH client or server.", "ssh.hassh:abc123" },
                { "ssh.type", "SSH key or service type.", "ssh.type:RSA" }
            }
        },

        {
            "Restricted",
            "Some filters are only available to users with eligible Shodan API plans.",
            {
                { "tag", "Search using Shodan tags. Plan restrictions may apply.", "tag:ics" },
                { "vuln", "Search for hosts associated with known vulnerabilities.", "vuln:CVE-2021-44228" }
            }
        }
    };

    // =========================================================
    // 创建分类卡片
    // =========================================================

    auto addCategory = [](const CategoryInfo& category) -> QGroupBox*
        {
            auto* groupBox = new QGroupBox(category.name);

            groupBox->setSizePolicy(
                QSizePolicy::Preferred,
                QSizePolicy::Maximum
            );

            auto* layout = new QVBoxLayout(groupBox);
            layout->setContentsMargins(12, 12, 12, 12);
            layout->setSpacing(8);

            auto* description = new QLabel(category.description);
            description->setWordWrap(true);
            description->setStyleSheet(
                "color: palette(mid);"
                "font-size: 12px;"
            );

            layout->addWidget(description);

            for (int i = 0; i < category.filters.size(); ++i)
            {
                const auto& filter = category.filters[i];

                auto* itemWidget = new QWidget();
                auto* itemLayout = new QVBoxLayout(itemWidget);

                itemLayout->setContentsMargins(0, 4, 0, 4);
                itemLayout->setSpacing(3);

                auto* nameLabel = new QLabel(filter.name);

                QFont nameFont = nameLabel->font();
                nameFont.setFamily("Consolas");
                nameFont.setBold(true);
                nameLabel->setFont(nameFont);

                nameLabel->setTextInteractionFlags(
                    Qt::TextSelectableByMouse
                );

                auto* detailLabel = new QLabel(filter.description);
                detailLabel->setWordWrap(true);
                detailLabel->setStyleSheet(
                    "color: palette(text);"
                    "font-size: 12px;"
                );

                auto* exampleLabel = new QLabel(filter.example);
                exampleLabel->setTextInteractionFlags(
                    Qt::TextSelectableByMouse
                );
                exampleLabel->setWordWrap(true);

                exampleLabel->setStyleSheet(
                    "QLabel {"
                    "  font-family: Consolas;"
                    "  font-size: 11px;"
                    "  color: palette(link);"
                    "  background-color: palette(alternate-base);"
                    "  border-radius: 3px;"
                    "  padding: 4px 6px;"
                    "}"
                );

                itemLayout->addWidget(nameLabel);
                itemLayout->addWidget(detailLabel);
                itemLayout->addWidget(exampleLabel);

                layout->addWidget(itemWidget);

                if (i != category.filters.size() - 1)
                {
                    auto* separator = new QFrame();

                    separator->setFrameShape(QFrame::HLine);
                    separator->setFrameShadow(QFrame::Plain);
                    separator->setStyleSheet(
                        "color: palette(mid);"
                    );

                    layout->addWidget(separator);
                }
            }

            return groupBox;
        };

    // =========================================================
    // 滚动区域
    // =========================================================

    auto* scrollArea = new QScrollArea();

    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    scrollArea->setHorizontalScrollBarPolicy(
        Qt::ScrollBarAsNeeded
    );

    scrollArea->setVerticalScrollBarPolicy(
        Qt::ScrollBarAsNeeded
    );

    auto* content = new QWidget();

    auto* contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(12);
    contentLayout->setAlignment(Qt::AlignTop);


    // =========================================================
    // 双列瀑布流布局
    // =========================================================

    auto* categoryContainer = new QWidget();

    auto* columnsLayout = new QHBoxLayout(categoryContainer);
    columnsLayout->setContentsMargins(0, 0, 0, 0);
    columnsLayout->setSpacing(16);

    auto* leftColumn = new QVBoxLayout();
    auto* rightColumn = new QVBoxLayout();

    leftColumn->setSpacing(16);
    rightColumn->setSpacing(16);

    int leftHeight = 0;
    int rightHeight = 0;

    for (const auto& category : categories)
    {
        auto* categoryWidget = addCategory(category);

        if (leftHeight <= rightHeight)
        {
            leftColumn->addWidget(categoryWidget);
            leftHeight += categoryWidget->sizeHint().height() + 16;
        }
        else
        {
            rightColumn->addWidget(categoryWidget);
            rightHeight += categoryWidget->sizeHint().height() + 16;
        }
    }

    leftColumn->addStretch();
    rightColumn->addStretch();

    columnsLayout->addLayout(leftColumn, 1);
    columnsLayout->addLayout(rightColumn, 1);

    contentLayout->addWidget(categoryContainer);

    // =========================================================
    // 搜索结果容器
    // =========================================================

    auto* resultsContainer = new QWidget();

    resultsContainer->setSizePolicy(
        QSizePolicy::Preferred,
        QSizePolicy::Maximum
    );

    auto* resultsLayout = new QVBoxLayout(resultsContainer);

    resultsLayout->setContentsMargins(0, 0, 0, 0);
    resultsLayout->setSpacing(4);
    resultsLayout->setAlignment(Qt::AlignTop);

    // 匹配数量
    auto* resultCountLabel = new QLabel();

    resultCountLabel->setSizePolicy(
        QSizePolicy::Preferred,
        QSizePolicy::Fixed
    );

    resultsLayout->addWidget(
        resultCountLabel,
        0,
        Qt::AlignTop
    );

    // =========================================================
    // 搜索结果卡片网格
    // =========================================================

    auto* resultGridWidget = new QWidget();

    resultGridWidget->setSizePolicy(
        QSizePolicy::Preferred,
        QSizePolicy::Maximum
    );

    auto* resultGridLayout = new QGridLayout(resultGridWidget);

    resultGridLayout->setContentsMargins(0, 0, 0, 0);
    resultGridLayout->setHorizontalSpacing(12);
    resultGridLayout->setVerticalSpacing(12);
    resultGridLayout->setAlignment(Qt::AlignTop | Qt::AlignLeft);

    // 两列等宽
    resultGridLayout->setColumnStretch(0, 1);
    resultGridLayout->setColumnStretch(1, 1);

    // 让两列卡片保持相同宽度
    resultGridLayout->setColumnMinimumWidth(0, 1);
    resultGridLayout->setColumnMinimumWidth(1, 1);

    resultsLayout->addWidget(
        resultGridWidget,
        0,
        Qt::AlignTop
    );

    contentLayout->addWidget(
        resultsContainer,
        0,
        Qt::AlignTop
    );

    resultsContainer->hide();

    scrollArea->setWidget(content);

    rootLayout->addWidget(scrollArea, 1);

    // =========================================================
    // 搜索结果生成
    // =========================================================

    auto updateSearchResults = [
        categories,
        resultGridLayout,
        resultGridWidget,
        resultCountLabel,
        categoryContainer,
        resultsContainer,
        resultsLayout,
        contentLayout
    ](const QString& keyword, const QString& categoryName)
        {
            // 清除旧结果卡片
            while (resultGridLayout->count() > 0)
            {
                QLayoutItem* item = resultGridLayout->takeAt(0);

                if (item->widget())
                    item->widget()->deleteLater();

                delete item;
            }

            const QString searchText = keyword.trimmed();

            int matchedCount = 0;

            // =================================================
            // 遍历过滤器
            // =================================================

            for (const auto& category : categories)
            {
                if (categoryName != "All" &&
                    category.name.compare(
                        categoryName,
                        Qt::CaseInsensitive
                    ) != 0)
                {
                    continue;
                }

                for (const auto& filter : category.filters)
                {
                    const bool matched =
                        searchText.isEmpty() ||
                        filter.name.contains(
                            searchText,
                            Qt::CaseInsensitive
                        ) ||
                        filter.description.contains(
                            searchText,
                            Qt::CaseInsensitive
                        ) ||
                        filter.example.contains(
                            searchText,
                            Qt::CaseInsensitive
                        );

                    if (!matched)
                        continue;

                    ++matchedCount;

                    // =========================================
                    // 创建结果卡片
                    // =========================================

                    auto* resultWidget = new QFrame();

                    resultWidget->setFrameShape(QFrame::StyledPanel);

                    resultWidget->setSizePolicy(
                        QSizePolicy::Expanding,
                        QSizePolicy::Fixed
                    );

                    resultWidget->setStyleSheet(
                        "QFrame {"
                        "  border: 1px solid palette(mid);"
                        "  border-radius: 6px;"
                        "}"
                    );

                    auto* resultLayout = new QVBoxLayout(resultWidget);

                    resultLayout->setContentsMargins(12, 8, 12, 8);
                    resultLayout->setSpacing(5);

                    // 名称和分类
                    auto* headerLayout = new QHBoxLayout();

                    auto* nameLabel = new QLabel(filter.name);

                    QFont font = nameLabel->font();
                    font.setFamily("Consolas");
                    font.setBold(true);

                    nameLabel->setFont(font);
                    nameLabel->setStyleSheet("border: none;");

                    auto* categoryLabel = new QLabel(category.name);

                    categoryLabel->setStyleSheet(
                        "color: palette(mid);"
                        "border: none;"
                        "font-size: 11px;"
                    );

                    headerLayout->addWidget(nameLabel);
                    headerLayout->addStretch();
                    headerLayout->addWidget(categoryLabel);

                    // 描述
                    auto* descriptionLabel = new QLabel(
                        filter.description
                    );

                    descriptionLabel->setWordWrap(true);

                    descriptionLabel->setStyleSheet(
                        "border: none;"
                    );

                    // 示例
                    auto* exampleLabel = new QLabel(filter.example);

                    exampleLabel->setTextInteractionFlags(
                        Qt::TextSelectableByMouse
                    );

                    exampleLabel->setWordWrap(true);

                    exampleLabel->setStyleSheet(
                        "QLabel {"
                        "  font-family: Consolas;"
                        "  color: palette(link);"
                        "  background-color: palette(alternate-base);"
                        "  border: none;"
                        "  border-radius: 3px;"
                        "  padding: 5px;"
                        "}"
                    );

                    // 复制按钮
                    auto* copyButton = new QToolButton();

                    copyButton->setText("Copy");
                    copyButton->setToolTip("Copy example query");
                    copyButton->setCursor(Qt::PointingHandCursor);

                    const QString example = filter.example;

                    QObject::connect(
                        copyButton,
                        &QToolButton::clicked,
                        copyButton,
                        [example]()
                        {
                            QApplication::clipboard()->setText(example);
                        }
                    );

                    auto* exampleLayout = new QHBoxLayout();

                    exampleLayout->addWidget(exampleLabel, 1);
                    exampleLayout->addWidget(copyButton);

                    resultLayout->addLayout(headerLayout);
                    resultLayout->addWidget(descriptionLabel);
                    resultLayout->addLayout(exampleLayout);

                    // =========================================
                    // 固定两列网格
                    // =========================================

                    const int index = matchedCount - 1;

                    const int row = index / 2;
                    const int column = index % 2;

                    resultGridLayout->addWidget(
                        resultWidget,
                        row,
                        column,
                        Qt::AlignTop
                    );
                }
            }

            // =================================================
            // 更新匹配数量
            // =================================================

            resultCountLabel->setText(
                QString("%1 matching filters").arg(matchedCount)
            );

            resultCountLabel->setStyleSheet(
                "color: palette(mid);"
                "font-size: 12px;"
                "padding: 4px;"
            );

            // =================================================
            // 切换显示模式
            // =================================================

            const bool showCategories =
                searchText.isEmpty() && categoryName == "All";

            categoryContainer->setVisible(showCategories);

            resultsContainer->setVisible(!showCategories);

            // =================================================
            // 无匹配结果
            // =================================================

            if (matchedCount == 0)
            {
                auto* emptyLabel = new QLabel(
                    "No matching filters found."
                );

                emptyLabel->setAlignment(Qt::AlignCenter);
                emptyLabel->setMinimumHeight(100);

                emptyLabel->setStyleSheet(
                    "color: palette(mid);"
                    "font-size: 14px;"
                );

                resultGridLayout->addWidget(
                    emptyLabel,
                    0,
                    0,
                    1,
                    2,
                    Qt::AlignTop
                );
            }

            // 立即更新布局的尺寸计算
            resultGridLayout->invalidate();
            resultsLayout->invalidate();
            contentLayout->invalidate();

            resultGridWidget->adjustSize();
            resultsContainer->adjustSize();
        };

    // =========================================================
    // 搜索框信号连接
    // =========================================================

    QObject::connect(
        searchEdit,
        &QLineEdit::textChanged,
        home,
        [updateSearchResults, home](const QString& text)
        {
            // 从 home 的 Property 读取分类
            const QString selectedCategory =
                home->property("selectedCategory").toString();

            updateSearchResults(
                text,
                selectedCategory
            );
        }
    );

    // =========================================================
    // 分类按钮事件
    // =========================================================

    for (auto* button : categoryButtons)
    {
        QObject::connect(
            button,
            &QToolButton::clicked,
            home,
            [button, home, searchEdit, updateSearchResults]()
            {
                // 保存当前分类
                home->setProperty(
                    "selectedCategory",
                    button->text()
                );

                updateSearchResults(
                    searchEdit->text(),
                    button->text()
                );
            }
        );
    }

    // =========================================================
    // 工具一：证书序列号 16 → 10 进制，查询 ssl.cert.serial
    // =========================================================
    connect(serialButton, &QPushButton::clicked, this, [this, serialEdit]() {
        const QString input = serialEdit->text().trimmed();
        if (input.isEmpty())
            return;
        const QString decimal = hexSerialToDecimal(input);
        if (decimal.isEmpty()) {
            QMessageBox::warning(this, "证书序列号",
                "无法解析的证书序列号。\n"
                "请输入合法的 16 进制字符串（允许包含冒号/空格），\n"
                "例如：04:9f:c2:a3:05:83:94:bc:a2:4e:b2:b3:0f:be:1b:a4");
            return;
        }
        // Shodan 的 ssl.cert.serial 以 10 进制整数索引（官方 banner 示例）
        queryEdit_->setText(QString("ssl.cert.serial:%1").arg(decimal));
        search();
        });

    // =========================================================
    // 工具二：下载 favicon → mmh3 → 查询 http.favicon.hash
    // 走独立 QNetworkAccessManager，不占用 Shodan API 请求队列
    // =========================================================
    connect(faviconButton, &QPushButton::clicked, this,
        [this, faviconEdit, faviconButton]() {
            QString urlStr = faviconEdit->text().trimmed();
            if (urlStr.isEmpty())
                return;
            if (!urlStr.startsWith("http://", Qt::CaseInsensitive)
                && !urlStr.startsWith("https://", Qt::CaseInsensitive))
                urlStr.prepend("https://");

            QUrl url(urlStr);
            if (!url.isValid() || url.host().isEmpty()) {
                QMessageBox::warning(this, "favicon hash", "无效的 URL。");
                return;
            }
            // 只粘贴了站点地址时自动补 /favicon.ico
            if (url.path().isEmpty() || url.path() == "/")
                url.setPath("/favicon.ico");

            faviconButton->setEnabled(false);
            faviconButton->setText("抓取中...");

            QNetworkRequest req(url);
            req.setTransferTimeout(10000);
            req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                QNetworkRequest::NoLessSafeRedirectPolicy);
            req.setRawHeader("User-Agent", "ShodanViewer/" SHODAN_VIEWER_VERSION);

            QNetworkReply* reply = faviconNam_->get(req);
            reply->ignoreSslErrors();   // 抓第三方站点图标，宽松处理证书问题

            connect(reply, &QNetworkReply::finished, this,
                [this, reply, faviconButton]() {
                    faviconButton->setEnabled(true);
                    faviconButton->setText("计算并查询");
                    reply->deleteLater();

                    if (reply->error() != QNetworkReply::NoError) {
                        QMessageBox::warning(this, "favicon hash",
                            QString("抓取 Favicon 失败：%1").arg(reply->errorString()));
                        return;
                    }
                    const QByteArray raw = reply->readAll();
                    if (raw.isEmpty()) {
                        QMessageBox::warning(this, "favicon hash", "Favicon 内容为空。");
                        return;
                    }

                    // mmh3.hash 返回有符号 32 位整数，Shodan 查询里常见负值
                    const qint32 hash = qint32(murmur3_32(faviconHashSource(raw)));
                    queryEdit_->setText(QString("http.favicon.hash:%1").arg(hash));
                    search();
                });
        });


    // =========================================================
    // Ctrl + F：聚焦搜索框
    // =========================================================

    auto* findShortcut = new QShortcut(
        QKeySequence::Find,
        home
    );

    QObject::connect(
        findShortcut,
        &QShortcut::activated,
        searchEdit,
        [searchEdit]()
        {
            searchEdit->setFocus();
            searchEdit->selectAll();
        }
    );

    //// =========================================================
    //// 页面底部提示
    //// =========================================================

    //auto* tipLabel = new QLabel(
    //    "Tip: Combine multiple filters to narrow down your search. "
    //    "For example: <code>apache country:GB port:443</code>"
    //);

    //tipLabel->setWordWrap(true);
    //tipLabel->setTextFormat(Qt::RichText);

    //tipLabel->setStyleSheet(
    //    "color: palette(mid);"
    //    "font-size: 12px;"
    //    "padding-top: 4px;"
    //);

    //rootLayout->addWidget(tipLabel);

    // =========================================================
    // 添加首页 Tab
    // =========================================================

    tabs_->addTab(home, "Home");
}


// ============================================================
// 创建查询标签页
// ============================================================

QueryTab* MainWindow::createQueryTab(const QString& query)
{
    auto* tab = new QueryTab(query, tabs_);

    // --------------------------------------------------------
    // 查询失败时隐藏当前 Tab 的加载动画
    // --------------------------------------------------------

    connect(
        client_, &ShodanClient::searchError,
        tab, [tab](const QString& failedQuery, int failedPage, const QString& err) {
            if (tab->query == failedQuery && tab->currentPage == failedPage) {
                tab->hideLoading();
                tab->statusLabel->setText("查询失败");
            }
        }
    );

    // 设置当前标签页的翻页回调
    tab->pageRequested = [this, tab](int page) {
        showPage(tab, page);
        };

    // 添加标签页
    QString tabTitle = query;

    if (tabTitle.length() > 24) {
        tabTitle = tabTitle.left(24) + "...";
    }

    const int index = tabs_->addTab(
        tab,
        tabTitle
    );

    // 自动切换到新建的查询标签页
    tabs_->setCurrentIndex(index);

    // --------------------------------------------------------
    // 双击查看完整 Banner / JSON
    // --------------------------------------------------------

    connect(
        tab->table,
        &QTableView::doubleClicked,
        this,
        [this, tab](const QModelIndex&) {
            showSelectedDetails(tab);
        }
    );

    // --------------------------------------------------------
    // 右键菜单
    // --------------------------------------------------------
    connect(tab->table, &QTableView::customContextMenuRequested,
        this, [this, tab](const QPoint& pos)
        {
            const QModelIndex index = tab->table->indexAt(pos);
            if (!index.isValid()) return;
            tab->table->selectRow(index.row());

            const QJsonObject obj = tab->model->matchAt(index.row());
            const QString module = lookup(obj, "_shodan.module").toString().toLower();
            const bool isHttpService = module.startsWith("http"); // http/https/http-proxy

            QMenu menu(this);
            QAction* details = menu.addAction("查看完整 Banner / JSON");
            QAction* copyIp = menu.addAction("复制 IP");
            QAction* copyJson = menu.addAction("复制完整 JSON");
            QAction* copyUrl = isHttpService ? menu.addAction("复制链接") : nullptr;
            QAction* chosen = menu.exec(tab->table->viewport()->mapToGlobal(pos));
            if (!chosen) return;

            if (chosen == details) {
                showSelectedDetails(tab);
            }
            else if (chosen == copyIp) {
                QApplication::clipboard()->setText(obj.value("ip_str").toString());
            }
            else if (chosen == copyJson) {
                QApplication::clipboard()->setText(QString::fromUtf8(
                    QJsonDocument(obj).toJson(QJsonDocument::Indented)));
            }
            else if (copyUrl && chosen == copyUrl) {
                QApplication::clipboard()->setText(buildHttpUrl(obj));
            }
        });

    return tab;
}


// ============================================================
// 获取当前查询标签页
// ============================================================

QueryTab* MainWindow::currentQueryTab() const
{
    return dynamic_cast<QueryTab*>(
        tabs_->currentWidget()
        );
}


// ============================================================
// 菜单
// ============================================================

void MainWindow::configureMenus()
{
    // 设置菜单
    auto* settingsMenu = menuBar()->addMenu("设置");

    settingsMenu->addAction(
        "API Key",
        this,
        &MainWindow::showApiKeyDialog
    );

    settingsMenu->addAction("代理设置", this, [this]() {
        ProxyDialog dlg(loadProxyConfig(), this);
        if (dlg.exec() == QDialog::Accepted) {
            const ProxyConfig c = dlg.result();
            saveProxyConfig(c);
            applyProxy(c);
            QMessageBox::information(this, "代理",
                c.enabled ? QString("代理已启用：%1:%2").arg(c.host).arg(c.port)
                : "代理已禁用。");
        }
    });

    settingsMenu->addAction(
        "刷新账户信息",
        client_,
        &ShodanClient::getApiInfo
    );

    // 缓存菜单
    auto* fileMenu = menuBar()->addMenu("缓存");

    fileMenu->addAction(
        "导出当前查询",
        this,
        &MainWindow::exportResults
    );

    fileMenu->addAction(
        "刷新当前查询",
        this,
        [this]() {

            QueryTab* tab = currentQueryTab();

            if (!tab) {
                QMessageBox::information(this, "刷新", "请先切换到一个查询标签页。");
                return;
            }

            //cache_->clearQuery(tab->query);
            cache_->clearQuery(tab->query, tab->currentPage);
            //tab->currentPage = 1;
            //tab->totalResults = 0;

            tab->model->setMatches(QJsonArray());

            tab->statusLabel->setText("正在刷新...");

            tab->updateNavigation();

            client_->count(tab->query);

            showPage(tab, tab->currentPage);
        }
    );
}


// --------------------------------------------------------
// 代理配置：读 / 存（settings.ini）/ 应用
// --------------------------------------------------------
ProxyConfig MainWindow::loadProxyConfig()
{
    ProxyConfig c;
    c.enabled = settings_.value("proxy/enabled", false).toBool();
    c.isHttp = settings_.value("proxy/type", "http").toString() != "socks5";
    c.host = settings_.value("proxy/host").toString();
    c.port = quint16(settings_.value("proxy/port", 0).toUInt());
    c.user = settings_.value("proxy/user").toString();
    c.password = settings_.value("proxy/password").toString();
    return c;
}

void MainWindow::saveProxyConfig(const ProxyConfig& c)
{
    settings_.setValue("proxy/enabled", c.enabled);
    settings_.setValue("proxy/type", c.isHttp ? "http" : "socks5");
    settings_.setValue("proxy/host", c.host);
    settings_.setValue("proxy/port", c.port);
    settings_.setValue("proxy/user", c.user);
    settings_.setValue("proxy/password", c.password);
    settings_.sync();
}

void MainWindow::applyProxy(const ProxyConfig& c)
{
    if (!c.enabled || c.host.isEmpty() || c.port == 0) {
        QNetworkProxy::setApplicationProxy(QNetworkProxy());  // NoProxy
        return;
    }
    QNetworkProxy proxy(
        c.isHttp ? QNetworkProxy::HttpProxy : QNetworkProxy::Socks5Proxy,
        c.host, c.port, c.user, c.password);
    QNetworkProxy::setApplicationProxy(proxy);
}


// ============================================================
// 执行查询
// ============================================================

void MainWindow::search()
{
    const QString query = queryEdit_->text().trimmed();

    if (query.isEmpty())
        return;

    // 保存最近查询记录
    queryEdit_->addHistory(query);


    // 每次查询都创建新的标签页
    QueryTab* tab = createQueryTab(query);

    tab->currentPage = 1;
    tab->totalResults = 0;

    tab->statusLabel->setText("正在查询...");

    tab->updateNavigation();

    // 查询总数量
    client_->count(query);

    // 请求第一页
    showPage(tab, 1);
}


// ============================================================
// 加载指定页
// ============================================================

void MainWindow::showPage(
    QueryTab* tab,
    int page
)
{
    if (!tab)
        return;

    if (page < 1)
        return;

    tab->currentPage = page;

    tab->updateNavigation();

    // --------------------------------------------------------
    // 优先使用 SQLite 缓存
    // --------------------------------------------------------

    if (const auto cached =
        cache_->getPage(tab->query, page)) {

        displayPage(tab, *cached);

        tab->statusLabel->setText(
            QString(
                "共 %1 条 · 当前页 %2 · SQLite 本地缓存"
            )
            .arg(tab->totalResults)
            .arg(tab->currentPage)
        );

        return;
    }

    // --------------------------------------------------------
    // 缓存不存在，显示加载动画
    // --------------------------------------------------------

    tab->showLoading();

    // --------------------------------------------------------
    // 请求 Shodan API
    // --------------------------------------------------------

    tab->statusLabel->setText(
        QString("正在请求 Shodan API · Page %1...")
        .arg(page)
    );

    client_->search(
        tab->query,
        page
    );
}


// ============================================================
// 显示搜索结果
// ============================================================

void MainWindow::displayPage(
    QueryTab* tab,
    const QJsonObject& data
)
{
    if (!tab)
        return;

    tab->model->setMatches(
        data.value("matches").toArray()
    );

    const int loaded =
        tab->model->rowCount();

    tab->statusLabel->setText(
        QString(
            "共 %1 条 · 当前页 %2 · 本页 %3 条"
        )
        .arg(tab->totalResults)
        .arg(tab->currentPage)
        .arg(loaded)
    );

    tab->updateNavigation();
    tab->hideLoading();
}


// ============================================================
// API Key 设置
// ============================================================

void MainWindow::showApiKeyDialog()
{
    bool ok = false;

    const QString key = QInputDialog::getText(
        this,
        "Shodan API Key",
        "API Key:",
        QLineEdit::Password,
        client_->apiKey(),
        &ok
    );

    if (!ok)
        return;

    client_->setApiKey(key.trimmed());

    settings_.setValue(
        "api/key",
        key.trimmed()
    );

    client_->getApiInfo();
}


// ============================================================
// 查看选中结果详情
// ============================================================

void MainWindow::showSelectedDetails(QueryTab* tab)
{
    if (!tab)
        return;

    const QModelIndex index =
        tab->table->currentIndex();

    if (!index.isValid())
        return;

    JsonDialog dialog(
        tab->model->matchAt(index.row()),
        this
    );

    dialog.exec();
}


// ============================================================
// 导出结果
// ============================================================

void MainWindow::exportResults()
{
    // 当前必须是查询标签页
    QueryTab* tab = currentQueryTab();
    if (!tab) {
        QMessageBox::information(this, "导出", "请先切换到一个查询标签页。");
        return;
    }

    const QString query = tab->query;

    bool ok = false;
    const int amount = QInputDialog::getInt(
        this, "导出", "导出前 N 条结果：",
        100, 1, 10000, 100, &ok);
    if (!ok) return;

    // --------------------------------------------------------
    // 页数规划：提前算好，供数据源选择框显示真实数字
    // --------------------------------------------------------
    const int pageSize = 100;
    int pages = (amount + pageSize - 1) / pageSize;
    if (tab->totalResults > 0)
        pages = qMin(pages, (tab->totalResults + pageSize - 1) / pageSize);

    // =========================================================
    // 数据源选择：缓存优先（默认）/ 全部重新请求
    // =========================================================
    const int cachedPages = cache_->cachedPageCount(query, pages);

    QDialog dlg(this);
    dlg.setWindowTitle("导出数据源");
    auto* lay = new QVBoxLayout(&dlg);
    lay->addWidget(new QLabel(
        QString("「%1」导出前 %2 条（共 %3 页）。\n本地缓存命中：%4 / %3 页。")
        .arg(query).arg(amount).arg(pages).arg(cachedPages), &dlg));

    auto* rbCache = new QRadioButton(
        QString("使用缓存，缺失页请求 API 补齐（约消耗 %1 credits）")
        .arg(pages - cachedPages), &dlg);
    auto* rbFresh = new QRadioButton(
        QString("全部重新请求（约消耗 %1 credits，数据最新）")
        .arg(pages), &dlg);
    rbCache->setChecked(true);   // 默认缓存优先，省 credits

    auto* btns = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    connect(btns, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(btns, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    lay->addWidget(rbCache);
    lay->addWidget(rbFresh);
    lay->addSpacing(6);
    lay->addWidget(btns);

    if (dlg.exec() != QDialog::Accepted) return;
    const bool useCache = rbCache->isChecked();

    const QString path = QFileDialog::getSaveFileName(
        this, "导出结果", "shodan_export.json",
        "JSON (*.json);;CSV (*.csv)");
    if (path.isEmpty()) return;

    QJsonArray all;

    QProgressDialog progress("正在导出...", "取消", 0, pages, this);
    progress.setWindowModality(Qt::WindowModal);
    progress.setMinimumDuration(0);
    progress.setValue(0);

    // 导出补抓期间：抑制全局 searchReady 的缓存写入等副作用
    exportingFetch_ = true;
    BoolGuard guard{ exportingFetch_ };

    QElapsedTimer lastApiCall;
    bool haveLastApiCall = false;
    int cacheHits = 0, apiCalls = 0;

    // --------------------------------------------------------
    // 逐页收集：缓存模式先查 SQLite，缺页走 API；全刷模式直接走 API
    // --------------------------------------------------------
    for (int p = 1; p <= pages && all.size() < amount; ++p) {
        progress.setValue(p - 1);
        progress.setLabelText(
            QString("正在导出：%1\n第 %2 / %3 页 · 缓存命中 %4 · API 请求 %5")
            .arg(query).arg(p).arg(pages).arg(cacheHits).arg(apiCalls));
        QCoreApplication::processEvents();

        if (progress.wasCanceled()) {
            if (all.isEmpty()) return;
            if (QMessageBox::question(this, "导出",
                QString("已获取 %1 条，是否保存已获取的部分？")
                .arg(all.size())) != QMessageBox::Yes)
                return;
            break;
        }

        // ---- 1) 本地缓存优先（仅“使用缓存”模式查询）----
        std::optional<QJsonObject> data;
        if (useCache)
            data = cache_->getPage(query, p);

        if (data) {
            ++cacheHits;
        }
        else {
            // ---- 2) 缺页 → 请求 API（限速：间隔 ≥ 1s）----
            if (haveLastApiCall) {
                const qint64 wait = kExportApiIntervalMs - lastApiCall.elapsed();
                if (wait > 0) {
                    QEventLoop pause;
                    QTimer::singleShot(int(wait), &pause, &QEventLoop::quit);
                    pause.exec();
                }
            }

            data = fetchPageBlocking(client_, query, p);
            lastApiCall.start();
            haveLastApiCall = true;
            ++apiCalls;

            if (!data) {
                if (all.isEmpty()) {
                    QMessageBox::warning(this, "导出失败",
                        QString("第 %1 页请求失败或超时。").arg(p));
                    return;
                }
                if (QMessageBox::question(this, "导出中断",
                    QString("第 %1 页请求失败或超时。\n"
                        "已获取 %2 条，是否保存这部分？\n"
                        "（本次已请求成功的页已写入本地缓存，"
                        "缺失页下次导出可继续补齐）")
                    .arg(p).arg(all.size())) != QMessageBox::Yes)
                    return;
                break;
            }

            // ---- 3) 回填本地缓存（两种模式都写）----
            //cache_->putPage(query, p, *data);
        }

        const QJsonArray matches = data->value("matches").toArray();
        for (const auto& item : matches) {
            if (all.size() >= amount) break;
            all.append(item);
        }
    }

    progress.setValue(pages);

    if (all.isEmpty()) {
        QMessageBox::information(this, "导出", "没有获取到任何数据。");
        return;
    }

    // --------------------------------------------------------
    // 写入文件（CSV / JSON，与你原逻辑一致）
    // --------------------------------------------------------
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "导出失败", file.errorString());
        return;
    }

    if (path.endsWith(".csv", Qt::CaseInsensitive)) {
        QTextStream out(&file);
        out << "ip,port,transport,service,hostnames,domains,"
            "title,server,product,version,org,isp,"
            "city,region,country,country_name,asn,os,"
            "tags,ssl_cn,ssl_expired,vulns,"
            "lat,lon,timestamp,banner\n";
        for (const auto& v : all) {
            const auto o = v.toObject();

            QStringList hostnames;
            for (const auto& x : o.value("hostnames").toArray())
                hostnames << x.toString();

            QStringList domains;
            for (const auto& x : o.value("domains").toArray())
                domains << x.toString();

            // 智能标题：http.title → 证书 CN
            QString title = o.value("http").toObject().value("title").toString();
            if (title.isEmpty())
                title = lookup(o, "ssl.cert.subject.cn").toString();

            // 证书过期：字段存在才输出 true/false
            const QJsonValue exp = lookup(o, "ssl.cert.expired");
            const QString sslExpired = exp.isUndefined()
                ? QString() : (exp.toBool() ? "true" : "false");

            const auto loc = o.value("location").toObject();

            // 收录时间：UTC → 本地
            const QDateTime dt = QDateTime::fromString(
                o.value("timestamp").toString(), Qt::ISODate);

            // 完整 banner：折叠换行，避免破坏 CSV 行结构
            QString banner = o.value("data").toString();
            banner.remove('\r');
            banner.replace('\n', "\\n");

            QStringList fields{
                o.value("ip_str").toString(),
                QString::number(o.value("port").toInt()),
                o.value("transport").toString(),                    // 传输层 tcp/udp
                lookup(o, "_shodan.module").toString(),             // 应用层 http/ssh/...
                hostnames.join(";"),
                domains.join(";"),
                title,
                o.value("http").toObject().value("server").toString(),
                o.value("product").toString(),
                o.value("version").toString(),
                o.value("org").toString(),
                o.value("isp").toString(),
                loc.value("city").toString(),
                loc.value("region").toString(),
                loc.value("country_code").toString(),
                loc.value("country_name").toString(),
                o.value("asn").toString(),
                o.value("os").toString(),
                joinArray(o.value("tags")),
                lookup(o, "ssl.cert.subject.cn").toString(),
                sslExpired,
                joinKeys(o.value("vulns")),                         // 免费套餐为空列
                loc.contains("latitude")
                    ? QString::number(loc.value("latitude").toDouble()) : QString(),
                loc.contains("longitude")
                    ? QString::number(loc.value("longitude").toDouble()) : QString(),
                dt.isValid()
                    ? dt.toLocalTime().toString("yyyy-MM-dd HH:mm:ss") : QString(),
                banner
            };

            // CSV 转义
            for (QString& f : fields)
                f = "\"" + f.replace("\"", "\"\"") + "\"";
            out << fields.join(",") << "\n";
        }
    }
    else {
        // JSON 分支保持不变：整条 banner 原样入库，无需增列
        file.write(QJsonDocument(all).toJson(QJsonDocument::Indented));
    }

    client_->getApiInfo();   // 补抓期间被抑制，导出结束后刷新一次 Credits

    QMessageBox::information(this, "导出完成",
        QString("已导出 %1 条。\n（缓存命中 %2 页 · API 请求 %3 页）")
        .arg(all.size()).arg(cacheHits).arg(apiCalls));
}

