#pragma once

#include <QString>
#include <QJsonObject>
#include <QSqlDatabase>
#include <optional>

class CacheStore
{
public:
    explicit CacheStore(const QString &databasePath);
    ~CacheStore();

    bool isOpen() const;
    QString errorString() const;
    std::optional<QJsonObject> getPage(const QString &query, int page);
    bool putPage(const QString &query, int page, const QJsonObject &data);
    int cachedPageCount(const QString& query, int maxPage) const;
    void clearQuery(const QString &query);
    void clearQuery(const QString& query, int page);

private:
    QSqlDatabase db_;
    QString connectionName_;
    QString error_;
};
