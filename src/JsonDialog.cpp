#include "JsonDialog.h"
#include <QPlainTextEdit>
#include <QVBoxLayout>
#include <QDialogButtonBox>
#include <QJsonDocument>

JsonDialog::JsonDialog(const QJsonObject &object, QWidget *parent) : QDialog(parent)
{
    setWindowTitle("Host / Banner Details");
    resize(820, 620);
    auto *layout = new QVBoxLayout(this);
    auto *editor = new QPlainTextEdit(this);
    editor->setReadOnly(true);
    editor->setLineWrapMode(QPlainTextEdit::NoWrap);
    editor->setPlainText(QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Indented)));
    editor->setStyleSheet("QPlainTextEdit { font-family: Consolas, 'Cascadia Code', monospace; font-size: 12px; }");
    layout->addWidget(editor);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
}
