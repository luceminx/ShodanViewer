#pragma once

#include <QObject>
#include <QNetworkAccessManager>
#include <QQueue>
#include <QJsonObject>
#include <QUrlQuery>

class ShodanClient : public QObject
{
    Q_OBJECT
public:
    explicit ShodanClient(QObject *parent = nullptr);

    void setApiKey(const QString &key);
    QString apiKey() const;

    void getApiInfo();
    void count(const QString &query);
    void search(const QString &query, int page);

signals:
    void apiInfoReady(const QJsonObject &data);
    void countReady(const QString &query, const QJsonObject &data);
    void searchReady(const QString &query, int page, const QJsonObject &data);
    void requestError(const QString &message);
    void searchError(const QString& query, int page, const QString& error);
private:
    struct Request {
        QUrl url;
        QByteArray operation;
        QString query;
        int page = 0;
    };

    QNetworkAccessManager manager_;
    QString apiKey_;
    QQueue<Request> queue_;
    bool busy_ = false;

    void enqueue(const Request &request);
    void startNext();
    void handleFinished(QNetworkReply *reply, const Request &request);
};
