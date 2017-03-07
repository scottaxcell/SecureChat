#ifndef SECURECHAT_H
#define SECURECHAT_H

#include <QMainWindow>

namespace Ui {
class SecureChat;
}

class SecureChat : public QMainWindow
{
    Q_OBJECT

public:
    explicit SecureChat(QWidget *parent = 0);
    explicit SecureChat(int argc, char **argv, QWidget *parent = 0);
    ~SecureChat();

protected:
    bool eventFilter(QObject *obj, QEvent *ev);

signals:
    void msgInput(QString);

public slots:
    void updateLog(QByteArray);

private:
    Ui::SecureChat *ui;
};

#endif // SECURECHAT_H
