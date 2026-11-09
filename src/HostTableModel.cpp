#include "HostTableModel.h"

namespace {
    // 嵌套路径取值："location.city"
    QJsonValue lookup(const QJsonObject& obj, const QString& path)
    {
        QJsonValue v = obj;
        for (const QString& p : path.split('.')) {
            if (!v.isObject()) return {};
            v = v.toObject().value(p);
        }
        return v;
    }



    QString joinArray(const QJsonValue& v)
    {
        QStringList items;
        for (const auto& x : v.toArray())
            items << x.toString();
        return items.join(';');
    }
}

HostTableModel::HostTableModel(QObject *parent) : QAbstractTableModel(parent) {}
int HostTableModel::rowCount(const QModelIndex &parent) const { return parent.isValid() ? 0 : matches_.size(); }
int HostTableModel::columnCount(const QModelIndex &parent) const { return parent.isValid() ? 0 : headers_.size(); }

QString HostTableModel::valueFor(const QJsonObject& obj, int column) const
{
    switch (column) {

        case ColHostnames:
            return joinArray(obj.value("hostnames"));

        case ColTitle: {
            // HTTP banner 取页面标题，非 HTTP 但有 TLS 时回退证书 CN
            QString t = obj.value("http").toObject().value("title").toString();
            if (t.isEmpty())
                t = lookup(obj, "ssl.cert.subject.cn").toString();
            return t;
        }

        case ColIP:
            return obj.value("ip_str").toString();

        case ColPort:
            return QString::number(obj.value("port").toInt());

        case ColDomains:
            return joinArray(obj.value("domains"));

        case ColTransport: {
            const QString m = lookup(obj, "_shodan.module").toString();
            if (!m.isEmpty()) return m;
            return obj.value("transport").toString();
        }
        case ColBanner: {
            // 原始 banner 只显示首行，超长截断
            QString s = obj.value("data").toString();
            const int nl = s.indexOf('\n');
            if (nl >= 0) s.truncate(nl);
            s = s.simplified();
            if (s.size() > 80) s = s.left(80) + "…";
            return s;
        }
    }
    return {};
}


QVariant HostTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= matches_.size()) return {};
    const QJsonObject obj = matches_.at(index.row()).toObject();
    if (role == Qt::DisplayRole) return valueFor(obj, index.column());
    if (role == Qt::ToolTipRole) {
        const QJsonObject m = matches_.at(index.row()).toObject();
        // Banner 列特殊处理：悬浮显示完整原文（表格里只显示截断的首行）
        if (index.column() == ColBanner) {
            QString banner = m.value("data").toString();
            if (banner.size() > 2000)
                banner = banner.left(2000) + "…";   // 超长 banner 防止 tooltip 巨大
            return banner;
        }
        // 其余列：显示本单元格内容
        return valueFor(m, index.column());
    }
    return {};
}

QVariant HostTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole) return {};
    if (orientation == Qt::Horizontal && section >= 0 && section < headers_.size()) return headers_.at(section);
    if (orientation == Qt::Vertical) return section + 1;
    return {};
}

void HostTableModel::setMatches(const QJsonArray &matches)
{
    beginResetModel();
    matches_ = matches;
    endResetModel();
}

QJsonObject HostTableModel::matchAt(int row) const
{
    if (row < 0 || row >= matches_.size()) return {};
    return matches_.at(row).toObject();
}
