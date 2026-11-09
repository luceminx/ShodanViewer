#pragma once
#include <QWidget>
#include <QTableView>
#include <QPushButton>
#include <QLabel>
#include <QMovie>
#include <QGridLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QAbstractItemView>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QStyle>
#include <QPainter>
#include <functional>
#include "HostTableModel.h"

class QTableView;
class HostTableModel;

// 选中行不显示虚线框
class NoFocusDelegate : public QStyledItemDelegate {
public:
    using QStyledItemDelegate::QStyledItemDelegate;
    void paint(QPainter* painter, const QStyleOptionViewItem& option,
        const QModelIndex& index) const override {
        QStyleOptionViewItem opt(option);
        opt.state &= ~QStyle::State_HasFocus;
        QStyledItemDelegate::paint(painter, opt, index);
    }
};

class QueryTab : public QWidget {
public:
    explicit QueryTab(const QString& queryText, QWidget* parent = nullptr)
        : QWidget(parent), query(queryText)
    {
        auto* root = new QVBoxLayout(this);
        root->setContentsMargins(6, 6, 6, 4);
        root->setSpacing(4);

        // 翻页区域
        auto* nav = new QHBoxLayout;
        prevButton = new QPushButton("上一页");
        nextButton = new QPushButton("下一页");
        pageLabel = new QLabel("Page 1");
        statusLabel = new QLabel("就绪");
        nav->addWidget(prevButton);
        nav->addWidget(nextButton);
        nav->addWidget(pageLabel);
        nav->addStretch();
        root->addLayout(nav);

        // 结果表格
        table = new QTableView(this);
        model = new HostTableModel(this);
        table->setModel(model);

        table->setColumnWidth(HostTableModel::ColHostnames, 180);
        table->setColumnWidth(HostTableModel::ColTitle, 220);
        table->setColumnWidth(HostTableModel::ColIP, 140);
        table->setColumnWidth(HostTableModel::ColPort, 55);
        table->setColumnWidth(HostTableModel::ColDomains, 150);
        table->setColumnWidth(HostTableModel::ColTransport, 60);

        // 加载动画
        loadingLabel = new QLabel(table->viewport());
        loadingLabel->setAlignment(Qt::AlignCenter);
        loadingLabel->setStyleSheet("background: transparent;");
        loadingLabel->setAttribute(Qt::WA_TransparentForMouseEvents);
        loadingMovie = new QMovie(":/nyancat.gif", QByteArray(), this);
        loadingLabel->setMovie(loadingMovie);
        auto* loadingLayout = new QGridLayout(table->viewport());
        loadingLayout->setContentsMargins(0, 0, 0, 0);
        loadingLayout->addWidget(loadingLabel, 0, 0, Qt::AlignCenter);
        loadingLabel->hide();

        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(false);
        table->setMouseTracking(false);
        table->viewport()->setMouseTracking(false);
        table->setStyleSheet(R"(
            QTableView::item { border: none; border-radius: 0px; padding: 2px; }
            QTableView::item:hover { background-color: transparent; border: none; }
            QTableView::item:selected { background-color: #CFE3FF; color: #202020; border: none; }
            QTableView::item:focus { outline: none; border: none; }
        )");
        table->setItemDelegate(new NoFocusDelegate(table));
        table->verticalHeader()->setDefaultSectionSize(27);
        table->verticalHeader()->setDefaultAlignment(Qt::AlignCenter);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        table->horizontalHeader()->setStretchLastSection(true);
        table->setContextMenuPolicy(Qt::CustomContextMenu);

        root->addWidget(table, 1);
        root->addWidget(statusLabel);

        connect(prevButton, &QPushButton::clicked, this, [this]() {
            if (currentPage > 1 && pageRequested) pageRequested(currentPage - 1);
            });
        connect(nextButton, &QPushButton::clicked, this, [this]() {
            const int maxPage = qMax(1, (totalResults + 99) / 100);
            if (currentPage < maxPage && pageRequested) pageRequested(currentPage + 1);
            });
        updateNavigation();
     
    }

    void updateNavigation() {
        const int maxPage = qMax(1, (totalResults + 99) / 100);
        prevButton->setEnabled(currentPage > 1);
        nextButton->setEnabled(currentPage < maxPage);
        pageLabel->setText(QString("Page %1 / %2").arg(currentPage).arg(maxPage));
    }

    void showLoading() { loadingLabel->show(); loadingMovie->start(); }
    void hideLoading() { loadingMovie->stop(); loadingLabel->hide(); }

    QString query;
    int currentPage = 1;
    int totalResults = 0;

    QTableView* table = nullptr;
    HostTableModel* model = nullptr;
    QPushButton* prevButton = nullptr;
    QPushButton* nextButton = nullptr;
    QLabel* pageLabel = nullptr;
    QLabel* statusLabel = nullptr;
    QLabel* loadingLabel = nullptr;
    QMovie* loadingMovie = nullptr;

    std::function<void(int)> pageRequested;
};
