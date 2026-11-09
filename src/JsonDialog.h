#pragma once
#include <QDialog>
#include <QJsonObject>

class JsonDialog : public QDialog
{
    Q_OBJECT
public:
    explicit JsonDialog(const QJsonObject &object, QWidget *parent = nullptr);
};
