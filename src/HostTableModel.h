#pragma once

#include <QAbstractTableModel>
#include <QJsonArray>
#include <QJsonObject>

class HostTableModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    explicit HostTableModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    void setMatches(const QJsonArray &matches);
    QJsonObject matchAt(int row) const;
    enum Column : int {
        ColHostnames = 0,
        ColTitle,       // http.title，为空时回退 ssl.cert.subject.cn
        ColIP,
        ColPort,
        ColDomains,     // 注册域名（区别于 hostnames）
        ColTransport,   // tcp / udp
        ColBanner,      // data 首行截断
        ColCount
    };

private:
    QJsonArray matches_;
    QStringList headers_{
        "主机", "标题", "IP", "端口", "域名", "协议", "Banner"
    };
    QString valueFor(const QJsonObject &obj, int column) const;
};
