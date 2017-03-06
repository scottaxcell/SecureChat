#ifndef CLIENT_H
#define CLIENT_H

#include <QObject>
#include <QTcpSocket>

class Client : public QObject
{
    Q_OBJECT
public:
    explicit Client(QObject *parent = 0);
    explicit Client(QString ip, quint16 port, QObject *parent = 0);

    void connectToServer();

signals:

public slots:
    void connected();
    void disconnected();
    void bytesWritten (qint64 bytes);
    void readyRead();


private:
    QString m_ip;
    quint16 m_port;
    QTcpSocket *m_socket;

};

#endif // CLIENT_H
