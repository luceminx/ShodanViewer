#pragma once
#include <QLabel>
#include <QLineEdit>
#include <QCompleter>
#include <QStringListModel>
#include <QPainter>
#include <QKeyEvent>
#include <QFontMetrics>
#include <QJsonObject>
#include <QApplication> 
#include <QWidget>  
#include <QMouseEvent>
#include <QTableView>
#include <functional>
// ============================================================
// Credits 圆环
// ============================================================
class CreditIndicator : public QLabel {
public:
    explicit CreditIndicator(QWidget* parent = nullptr) : QLabel(parent) {
        setFixedSize(42, 42);
        setAlignment(Qt::AlignCenter);
        setCursor(Qt::PointingHandCursor);
        setToolTip("正在获取账户信息...");
    }

    void setAccountInfo(const QJsonObject& data) {
        credits_ = data.value("query_credits").toInt(-1);
        scanCredits_ = data.value("scan_credits").toInt(-1);
        plan_ = data.value("plan").toString("Unknown");

        const int totalCredits_ = 100;
        if (credits_ >= 0 && totalCredits_ > 0)
            percentage_ = qBound(0, credits_ * 100 / totalCredits_, 100);
        else
            percentage_ = -1;

        const QString percentText = percentage_ >= 0 ? QString("%1%").arg(percentage_) : QString("--");
        setToolTip(QString(
            "<b>Shodan Account</b><br>"
            "Plan: %1<br>"
            "Query Credits: %2<br>"
            "Scan Credits: %3<br>"
            "Remaining: %4")
            .arg(plan_)
            .arg(credits_ >= 0 ? QString::number(credits_) : "Unknown")
            .arg(scanCredits_ >= 0 ? QString::number(scanCredits_) : "Unknown")
            .arg(percentText));
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        const QRectF rect(5, 5, 32, 32);

        QPen backgroundPen(QColor("#DCE5F0"), 3.5);
        painter.setPen(backgroundPen);
        painter.setBrush(Qt::NoBrush);
        painter.drawEllipse(rect);

        if (percentage_ >= 0) {
            QPen progressPen(QColor("#2684FF"), 3.5);
            progressPen.setCapStyle(Qt::RoundCap);
            painter.setPen(progressPen);
            const int span = percentage_ * 360 * 16 / 100;
            painter.drawArc(rect, 90 * 16, -span);
        }

        painter.setPen(palette().color(QPalette::WindowText));
        QFont font = painter.font();
        font.setPixelSize(10);
        font.setBold(true);
        painter.setFont(font);
        painter.drawText(rect, Qt::AlignCenter,
            percentage_ >= 0 ? QString("%1%").arg(percentage_) : "--");
    }

private:
    int credits_ = -1;
    int scanCredits_ = -1;
    int percentage_ = -1;
    QString plan_ = "Unknown";
};

// ============================================================
// 搜索框行内自动补全
// ============================================================
class InlineCompleter : public QLineEdit {
public:
    explicit InlineCompleter(QWidget* parent = nullptr) : QLineEdit(parent) {
        filters_ = {
            "all", "asn", "asset", "city", "country", "cpe", "device", "domain",
            "geo", "google_ads", "google_analytics", "google_tag_manager",
            "has_ipv6", "has_screenshot", "has_ssl", "has_vuln", "hash",
            "hostname", "ip", "isp", "link", "meta_pixel", "net", "org", "os",
            "port", "postal", "product", "region", "scan", "shodan.module",
            "state", "tiktok_pixel", "version", "x_pixel",
            "http.component", "http.component_category", "http.dom_hash",
            "http.favicon.hash", "http.headers_hash", "http.html",
            "http.html_hash", "http.robots_hash", "http.securitytxt",
            "http.server_hash", "http.status", "http.title", "http.title_hash",
            "http.waf", "ssl", "ssl.alpn", "ssl.cert.alg", "ssl.cert.expired",
            "ssl.cert.extension", "ssl.cert.fingerprint", "ssl.cert.issuer.cn",
            "ssl.cert.pubkey.bits", "ssl.cert.pubkey.type", "ssl.cert.serial",
            "ssl.cert.subject.cn", "ssl.chain_count", "ssl.cipher.bits",
            "ssl.cipher.name", "ssl.cipher.version", "ssl.ja3s", "ssl.jarm",
            "ssl.version", "cloud.provider", "cloud.region", "cloud.service",
            "bitcoin.ip", "bitcoin.ip_count", "bitcoin.port", "bitcoin.version",
            "snmp.contact", "snmp.location", "snmp.name", "ntp.ip",
            "ntp.ip_count", "ntp.more", "ntp.port", "telnet.do", "telnet.dont",
            "telnet.option", "telnet.will", "telnet.wont", "ssh.hassh",
            "ssh.type", "screenshot.hash", "screenshot.label", "tag", "vuln",
            "before", "after"
        };

        connect(this, &QLineEdit::textChanged, this, [this]() { updateSuggestion(); });
        connect(this, &QLineEdit::cursorPositionChanged, this, [this]() { updateSuggestion(); });

        historyModel_ = new QStringListModel(this);
        historyCompleter_ = new QCompleter(historyModel_, this);
        historyCompleter_->setCaseSensitivity(Qt::CaseInsensitive);
        historyCompleter_->setFilterMode(Qt::MatchStartsWith);
        historyCompleter_->setCompletionMode(QCompleter::PopupCompletion);
        setCompleter(historyCompleter_);
    }

    void addHistory(const QString& query) {
        const QString value = query.trimmed();
        if (value.isEmpty()) return;
        history_.removeAll(value);
        history_.prepend(value);
        while (history_.size() > 5) history_.removeLast();
        historyModel_->setStringList(history_);
    }

protected:
    void paintEvent(QPaintEvent* event) override {
        QLineEdit::paintEvent(event);
        if (suggestion_.isEmpty() || !hasFocus() || cursorPosition() != text().size())
            return;

        QPainter painter(this);
        painter.setFont(font());
        painter.setPen(QColor("#999999"));
        const QFontMetrics fm(font());
        const int x = cursorRect().left() + 6;
        const QRect textRect = contentsRect();
        const int baseline = textRect.top() + (textRect.height() - fm.height()) / 2 + fm.ascent();
        painter.drawText(x, baseline, suggestion_);
    }

    bool event(QEvent* event) override {
        if (event->type() == QEvent::KeyPress) {
            auto* keyEvent = static_cast<QKeyEvent*>(event);
            if (keyEvent->key() == Qt::Key_Tab && !suggestion_.isEmpty()) {
                insert(suggestion_);
                keyEvent->accept();
                return true;
            }
            if (keyEvent->key() == Qt::Key_Escape && !suggestion_.isEmpty()) {
                suggestion_.clear();
                update();
                keyEvent->accept();
                return true;
            }
            // ---- Enter：提交弹窗选中项，切断两条回退路径 ----
            if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter) {
                if (QCompleter* c = completer()) {
                    QAbstractItemView* popup = c->popup();
                    if (popup && popup->isVisible()) {
                        // 1) 以弹窗选区为准取选中项（这才是 Down 导航的结果）
                        QString finalText;
                        const QModelIndex sel = popup->selectionModel()->currentIndex();
                        if (sel.isValid())
                            finalText = sel.data(Qt::EditRole).toString();
                        if (finalText.isEmpty())
                            finalText = c->currentCompletion();
                        if (finalText.isEmpty())
                            finalText = text();

                        // 2) 同步补全前缀：中和 "选区清空 → highlighted(prefix)
                        //    → setText(prefix)" 级联，之后写回的都是完整语句
                        c->setCompletionPrefix(finalText);
                        setText(finalText);
                        popup->hide();

                        // 3) 手动触发搜索并拦截事件，completer 的 Key_Return
                        //    分支（activated → setText 二次写入）不再执行
                        keyEvent->accept();
                        emit returnPressed();
                        return true;
                    }
                }
            }
        }
        return QLineEdit::event(event);
    }




private:
    QStringList filters_;
    QString suggestion_;
    QStringList history_;
    QStringListModel* historyModel_ = nullptr;
    QCompleter* historyCompleter_ = nullptr;

    void updateSuggestion() {
        suggestion_.clear();
        if (!hasFocus() || cursorPosition() != text().size()) { update(); return; }

        const QString currentText = text();
        const int lastSpace = currentText.lastIndexOf(' ');
        const QString token = currentText.mid(lastSpace + 1);
        if (token.isEmpty() || token.contains(':')) { update(); return; }

        for (const QString& filter : filters_) {
            if (filter.startsWith(token, Qt::CaseInsensitive)) {
                suggestion_ = filter.mid(token.length()) + ":";
                break;
            }
        }
        update();
    }
};

// ============================================================
// 表格空白处点击取消选中
// ============================================================
class TableBlankClickFilter : public QObject {
public:
    using TableProvider = std::function<QTableView* ()>;

    TableBlankClickFilter(TableProvider provider, QObject* parent)
        : QObject(parent), provider_(std::move(provider))
    {
        qApp->installEventFilter(this);   // 关键锚点：应用级，拦截一切
    }

    ~TableBlankClickFilter() override
    {
        qApp->removeEventFilter(this);
    }

protected:
    bool eventFilter(QObject* watched, QEvent* event) override {
        if (event->type() == QEvent::MouseButtonPress) {
            auto* me = static_cast<QMouseEvent*>(event);
            QTableView* table = provider_ ? provider_() : nullptr;
            if (me->button() == Qt::LeftButton && table && table->isVisible()) {
                QWidget* clicked = QApplication::widgetAt(
                    me->globalPosition().toPoint());
                // 同窗口才处理：排除 JSON 对话框、右键菜单、补全窗口、消息框
                if (clicked && clicked->window() == table->window()
                    && clicked != table
                    && !table->isAncestorOf(clicked)) {   // 表格自身/视口/滚动条/表头除外
                    table->clearSelection();
                    table->setCurrentIndex(QModelIndex());
                }
            }
        }
        return QObject::eventFilter(watched, event);
    }

private:
    TableProvider provider_;
};