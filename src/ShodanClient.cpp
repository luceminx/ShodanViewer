#include "ShodanClient.h"

#include <version.h>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QTimer>
#include <QUrl>

ShodanClient::ShodanClient(QObject *parent) : QObject(parent) {}

void ShodanClient::setApiKey(const QString &key) { apiKey_ = key.trimmed(); }
QString ShodanClient::apiKey() const { return apiKey_; }

void ShodanClient::getApiInfo()
{
    if (apiKey_.isEmpty()) {
        emit requestError("请先设置 Shodan API Key。");
        return;
    }
    QUrl url("https://api.shodan.io/api-info");
    QUrlQuery q; q.addQueryItem("key", apiKey_); url.setQuery(q);
    enqueue({url, "api-info", {}, 0});
}

void ShodanClient::count(const QString &query)
{
    if (apiKey_.isEmpty()) { emit requestError("请先设置 Shodan API Key。"); return; }
    QUrl url("https://api.shodan.io/shodan/host/count");
    QUrlQuery q; q.addQueryItem("key", apiKey_); q.addQueryItem("query", query);
    url.setQuery(q);
    enqueue({url, "count", query, 0});
}

void ShodanClient::search(const QString& query, int page)
{
    if (apiKey_.isEmpty()) {

        const QString error = "请先设置 Shodan API Key。";

        emit searchError(query, page, error);
        emit requestError(error);

        return;
    }

    QUrl url("https://api.shodan.io/shodan/host/search");

    QUrlQuery q;

    q.addQueryItem("key", apiKey_);
    q.addQueryItem("query", query);
    q.addQueryItem("page", QString::number(page));
    q.addQueryItem("minify", "false");

    url.setQuery(q);

    enqueue({ url, "search", query, page });
}

void ShodanClient::enqueue(const Request &request)
{
    queue_.enqueue(request);
    startNext();
}

void ShodanClient::startNext()
{
    if (busy_ || queue_.isEmpty()) return;
    busy_ = true;
    const Request request = queue_.dequeue();

    QNetworkRequest netRequest(request.url);
    netRequest.setHeader(QNetworkRequest::UserAgentHeader, "ShodanViewer/" SHODAN_VIEWER_VERSION);
    netRequest.setTransferTimeout(30000);
    QNetworkReply *reply = manager_.get(netRequest);
    connect(reply, &QNetworkReply::finished, this, [this, reply, request]() {
        handleFinished(reply, request);
        reply->deleteLater();
        
        // Keep requests serialized; a small gap avoids bursty calls.
        QTimer::singleShot(1100, this, [this]() { 
            busy_ = false;
            startNext(); 
        });
    });
}

void ShodanClient::handleFinished(QNetworkReply *reply, const Request &request)
{
    const QByteArray body = reply->readAll();
    if (reply->error() != QNetworkReply::NoError) {

        QString detail = QString::fromUtf8(body);

        if (detail.isEmpty())
            detail = reply->errorString();

        QString error = QString(
            "Shodan API 请求失败 (HTTP %1)：%2"
        )
            .arg(reply->attribute(
                QNetworkRequest::HttpStatusCodeAttribute
            ).toInt())
            .arg(detail);

        if (request.operation == "search")
            emit searchError(request.query, request.page, error);

        emit requestError(error);

        return;
    }

    QJsonParseError parseError;
    const auto doc = QJsonDocument::fromJson(body, &parseError);
    if (parseError.error != QJsonParseError::NoError ||
        !doc.isObject()) {

        QString error = "Shodan API 返回了无法解析的 JSON。";

        if (request.operation == "search")
            emit searchError(request.query, request.page, error);

        emit requestError(error);

        return;
    }
    const QJsonObject obj = doc.object();
    if (request.operation == "api-info") emit apiInfoReady(obj);
    else if (request.operation == "count") emit countReady(request.query, obj);
    else if (request.operation == "search") emit searchReady(request.query, request.page, obj);
}
