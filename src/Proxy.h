#pragma once
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QRadioButton>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QIntValidator>
#include <QMessageBox>

// 代理配置数据 + 编辑对话框（仿 Fofa_Viewer 交互）
struct ProxyConfig {
    bool    enabled = false;
    bool    isHttp = true;     // true=HTTP  false=SOCKS5
    QString host;
    quint16 port = 0;
    QString user;
    QString password;
};

class ProxyDialog : public QDialog {
public:
    explicit ProxyDialog(const ProxyConfig& cur, QWidget* parent = nullptr)
        : QDialog(parent)
    {
        setWindowTitle("代理配置");
        setModal(true);
        setMinimumWidth(320);

        auto* lay = new QVBoxLayout(this);

        // 启用 / 禁用
        auto* enableRow = new QHBoxLayout;
        enableRow->addStretch(1);
        enableOn_ = new QRadioButton("启用");
        enableOff_ = new QRadioButton("禁用");
        enableRow->addWidget(enableOn_);
        enableRow->addWidget(enableOff_);
        enableRow->addStretch(1);
        lay->addLayout(enableRow);

        // 表单
        auto* form = new QFormLayout;
        type_ = new QComboBox;
        type_->addItem("HTTP");
        type_->addItem("SOCKS5");
        form->addRow("类型：", type_);

        host_ = new QLineEdit;
        form->addRow("IP 地址：", host_);

        port_ = new QLineEdit;
        port_->setValidator(new QIntValidator(1, 65535, port_));
        form->addRow("端口：", port_);

        user_ = new QLineEdit;
        form->addRow("用户名：", user_);

        pass_ = new QLineEdit;
        pass_->setEchoMode(QLineEdit::Password);
        form->addRow("密码：", pass_);

        lay->addLayout(form);

        // 底部按钮
        auto* btnRow = new QHBoxLayout;
        btnRow->addStretch(1);
        ok_ = new QPushButton("确定");
        cancel_ = new QPushButton("取消");
        btnRow->addWidget(ok_);
        btnRow->addWidget(cancel_);
        lay->addLayout(btnRow);

        // 确定时校验：启用状态下 host/port 必填
        connect(ok_, &QPushButton::clicked, this, [this]() {
            if (enableOn_->isChecked()) {
                const bool okPort = port_->text().toUShort() != 0;
                if (host_->text().trimmed().isEmpty() || !okPort) {
                    QMessageBox::warning(this, "代理配置",
                        "启用代理时，IP 地址和端口不能为空。");
                    return;
                }
            }
            accept();
            });
        connect(cancel_, &QPushButton::clicked, this, &QDialog::reject);

        // 载入当前配置
        enableOn_->setChecked(cur.enabled);
        enableOff_->setChecked(!cur.enabled);
        type_->setCurrentIndex(cur.isHttp ? 0 : 1);
        host_->setText(cur.host);
        port_->setText(cur.port ? QString::number(cur.port) : QString());
        user_->setText(cur.user);
        pass_->setText(cur.password);
    }

    ProxyConfig result() const {
        ProxyConfig c;
        c.enabled = enableOn_->isChecked();
        c.isHttp = (type_->currentIndex() == 0);
        c.host = host_->text().trimmed();
        c.port = quint16(port_->text().toUShort());
        c.user = user_->text();
        c.password = pass_->text();
        return c;
    }

private:
private:
    QRadioButton* enableOn_ = nullptr;
    QRadioButton* enableOff_ = nullptr;
    QComboBox* type_ = nullptr;
    QLineEdit* host_ = nullptr;
    QLineEdit* port_ = nullptr;
    QLineEdit* user_ = nullptr;
    QLineEdit* pass_ = nullptr;
    QPushButton* ok_ = nullptr;
    QPushButton* cancel_ = nullptr;
};

