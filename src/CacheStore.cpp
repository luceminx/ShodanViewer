#include "CacheStore.h"

#include <QSqlQuery>
#include <QSqlError>
#include <QJsonDocument>
#include <QVariant>

CacheStore::CacheStore(const QString &databasePath)
{
    connectionName_ = "ShodanViewerCache";
    db_ = QSqlDatabase::addDatabase("QSQLITE", connectionName_);
    db_.setDatabaseName(databasePath);
    if (!db_.open()) { error_ = db_.lastError().text(); return; }

    QSqlQuery q(db_);
    if (!q.exec(R"(
        CREATE TABLE IF NOT EXISTS search_pages (
            query TEXT NOT NULL,
            page INTEGER NOT NULL,
            fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            payload BLOB NOT NULL,
            PRIMARY KEY(query, page)
        )
    )")) error_ = q.lastError().text();
}

CacheStore::~CacheStore()
{
    if (db_.isValid()) {
        db_.close();
        db_ = QSqlDatabase();
        QSqlDatabase::removeDatabase(connectionName_);
    }
}

bool CacheStore::isOpen() const { return db_.isOpen(); }
QString CacheStore::errorString() const { return error_; }

std::optional<QJsonObject> CacheStore::getPage(const QString &query, int page)
{
    QSqlQuery q(db_);
    q.prepare("SELECT payload FROM search_pages WHERE query=? AND page=?");
    q.addBindValue(query.trimmed());
    q.addBindValue(page);
    if (!q.exec() || !q.next()) return std::nullopt;
    const auto doc = QJsonDocument::fromJson(q.value(0).toByteArray());
    if (!doc.isObject()) return std::nullopt;
    return doc.object();
}

bool CacheStore::putPage(const QString &query, int page, const QJsonObject &data)
{
    QSqlQuery q(db_);
    q.prepare("INSERT OR REPLACE INTO search_pages(query,page,payload) VALUES(?,?,?)");
    q.addBindValue(query.trimmed());
    q.addBindValue(page);
    q.addBindValue(QJsonDocument(data).toJson(QJsonDocument::Compact));
    if (!q.exec()) { error_ = q.lastError().text(); return false; }
    return true;
}

int CacheStore::cachedPageCount(const QString& query, int maxPage) const
{
    QSqlQuery q(db_);
    q.prepare("SELECT COUNT(*) FROM search_pages WHERE query=? AND page<=?");
    q.addBindValue(query.trimmed());
    q.addBindValue(maxPage);
    if (!q.exec() || !q.next()) return 0;
    return q.value(0).toInt();
}

void CacheStore::clearQuery(const QString &query)
{
    QSqlQuery q(db_);
    q.prepare("DELETE FROM search_pages WHERE query=?");
    q.addBindValue(query.trimmed());
    q.exec();
}

void CacheStore::clearQuery(const QString& query, int page)
{
    QSqlQuery q(db_);
    q.prepare("DELETE FROM search_pages WHERE query=? AND page=?");
    q.addBindValue(query.trimmed());
    q.addBindValue(page);
    q.exec();
}
