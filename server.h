#ifndef SERVER_H
#define SERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>

class Server : public QTcpServer
{
    Q_OBJECT
public:
    explicit Server(QObject *parent = 0);
    explicit Server(quint16 port, QObject *parent = 0);

    void initialize();

protected:
    void incomingConnection(qintptr handle);

signals:

public slots:
    //void connected();
    void disconnected();
    void bytesWritten (qint64 bytes);
    void readyRead();

private:
    quint16 m_port;
    QString m_ip;
    QTcpSocket *m_clientSocket;

};

#endif // SERVER_H
