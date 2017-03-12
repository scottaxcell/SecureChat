#ifndef CLIENT_H
#define CLIENT_H

#include <QObject>
#include <QTcpSocket>

#include "util.h"

class Client : public QObject
{
    Q_OBJECT
public:
    explicit Client(QObject *parent = 0);
    explicit Client(QString ip, quint16 port, RSA *pubRSA, RSA *privRSA, QObject *parent = 0);

    // Connects to a server
    void connectToServer();

    // Initializes thread with this object
    void initialize(QThread &t);

signals:
    // Notifies GUI when socket receives a message
    void msgReceived(QByteArray);

    // Notifies the GUI to write to the textBrowser
    void statusUpdate(QString);

public slots:
    // QTcpSocket callbacks
    void connected();
    void disconnected();
    void bytesWritten (qint64 bytes);
    void readyRead();

    // Threading workhorse
    void run();

    // GUI calls this when user wants to send a message
    void sendMsg(QString);

private:
    QString m_ip;
    quint16 m_port;
    QTcpSocket *m_socket;
    RSA *m_pubRSA;
    RSA *m_privRSA;
    QByteArray m_passphrase;

    QByteArray encryptData(RSA *rsa, QByteArray &data);
    QByteArray decryptData(RSA *rsa, QByteArray &data);
};

#endif // CLIENT_H
