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
    explicit SecureChat(QStringList args, QWidget *parent = 0);
    ~SecureChat();

protected:
    bool eventFilter(QObject *obj, QEvent *ev);

signals:
    // Notifies a thread that the user has input a message to send
    void msgInput(QString);

public slots:
    // Writes to the textBrowser when notified by a thread
    void updateLog(QByteArray);
    void updateLog(QString);

private:
    Ui::SecureChat *ui;
};

#endif // SECURECHAT_H
