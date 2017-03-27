#ifndef SERVER_H
#define SERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>

#include "util.h"

class Server : public QTcpServer
{
    Q_OBJECT
public:
    explicit Server(RSA *pubRSA, RSA *privRSA, QObject *parent = 0);

    // Initializes thread with this object
    void initialize(QThread &t);

protected:
    void incomingConnection(qintptr handle);

signals:
    // Notifies GUI when socket receives a message
    void msgReceived(QByteArray);

    // Notifies the GUI to write to the textBrowser
    void statusUpdate(QString);

public slots:
    // QTcpSocket callbacks
    void disconnected();
    void bytesWritten (qint64 bytes);
    void readyRead();

    // Threading workhorse
    void run();

    // GUI calls this when user wants to send a message
    void sendMsg(QString);

    // GUI calls this when user wants to send a file
    void sendFile(QString);

private:
    quint16 m_port;
    QString m_ip;
    QTcpSocket *m_socket;
    RSA *m_pubRSA;
    RSA *m_privRSA;
    bool m_useAES;
    QByteArray m_passphrase;


    QByteArray encryptData(RSA *rsa, QByteArray &data);
    QByteArray decryptData(RSA *rsa, QByteArray &data);

};

#endif // SERVER_H
