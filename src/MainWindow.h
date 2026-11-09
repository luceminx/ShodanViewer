
#pragma once

#include <QMainWindow>
#include <QSettings>
#include <QJsonObject>
#include <QScrollArea>
#include <QGridLayout>
#include <QGroupBox>
#include <QFrame>
#include <QSizePolicy>
#include <QLineEdit>
#include <QCompleter>
#include <QStringListModel>
#include <QPainter>
#include <QKeyEvent>
#include <QFontMetrics>
#include <QColor>
#include <QEvent>

class QLineEdit;
class QPushButton;
class QTabWidget;
class ShodanClient;
class CacheStore;
class CreditIndicator;
class QueryTab;
class InlineCompleter;
class QNetworkAccessManager;
struct ProxyConfig;


class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private:
    // 核心组件
    ShodanClient* client_;
    CacheStore* cache_;
    QSettings settings_;

    // 主窗口控件
    //QLineEdit* queryEdit_ = nullptr;
    InlineCompleter* queryEdit_;
    QPushButton* searchButton_ = nullptr;
    QTabWidget* tabs_ = nullptr;
    CreditIndicator* accountLabel_ = nullptr;
    QNetworkAccessManager* faviconNam_ = nullptr;
    bool exportingFetch_ = false;

    // UI 初始化
    void configureUi();
    void configureMenus();

    // 标签页管理
    void createHomeTab();
    QueryTab* createQueryTab(const QString& query);
    QueryTab* currentQueryTab() const;

    // 查询和分页
    void search();
    void showPage(QueryTab* tab, int page);
    void displayPage(QueryTab* tab, const QJsonObject& data);

    // 其他功能
    void showApiKeyDialog();
    void exportResults();
    void showSelectedDetails(QueryTab* tab);

    ProxyConfig loadProxyConfig();
    void saveProxyConfig(const ProxyConfig& c);
    void applyProxy(const ProxyConfig& c);

};
