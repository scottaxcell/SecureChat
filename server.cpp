#include "server.h"

#include <QtCore>
#include <QHostAddress>
#include <QNetworkInterface>

Server::Server(QObject *parent) :
    QTcpServer(parent)
{
    m_clientSocket = nullptr;
}

void Server::initialize(QThread &t)
{
    connect(&t, SIGNAL(started()), this, SLOT(run()));
}

void Server::incomingConnection(qintptr handle)
{
    qDebug() << "Server has incoming client connection";
    m_clientSocket = new QTcpSocket();
    if (!m_clientSocket->setSocketDescriptor(handle)) {
        qDebug() << m_clientSocket->errorString();
        return;
    }

    connect(m_clientSocket, SIGNAL(bytesWritten(qint64)), this, SLOT(bytesWritten(qint64)), Qt::DirectConnection);
    connect(m_clientSocket, SIGNAL(disconnected()), this, SLOT(disconnected()), Qt::DirectConnection);
    connect(m_clientSocket, SIGNAL(readyRead()), this, SLOT(readyRead()), Qt::DirectConnection);

    qDebug() << "Server has connected with client successfully";

    QHostAddress addr = m_clientSocket->peerAddress();
    quint16 port = m_clientSocket->peerPort();
    QString msg = "Connected to client at " + addr.toString() + ":" + QString::number(port) + " successfully";
    emit statusUpdate(msg);
}

void Server::disconnected()
{
    qDebug() << "Server disconnected from client";
    QHostAddress addr = m_clientSocket->peerAddress();
    quint16 port = m_clientSocket->peerPort();
    QString msg = "Client at " + addr.toString() + ":" + QString::number(port) + " disconnected";
    emit statusUpdate(msg);
    m_clientSocket->deleteLater();
}

void Server::bytesWritten(qint64 bytes)
{
    qDebug() << "Client wrote" << bytes << "bytes";
}

void Server::readyRead()
{
    qDebug() << "Server readyRead";
    //qDebug() << m_clientSocket->readAll();
    emit msgReceived(m_clientSocket->readAll());
}

void Server::run()
{
    QHostAddress ip;
    foreach (const QHostAddress &address, QNetworkInterface::allAddresses()) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol && address != QHostAddress(QHostAddress::LocalHost))
            ip = address;
    }
    if (this->listen(ip, 0)) {
        QString msg = "Listening for a client connection on " + ip.toString() + ":" + QString::number(this->serverPort());
        qDebug() << msg;
        emit statusUpdate(msg);
    } else {
        qDebug() << "Server failed to start";
    }
}

void Server::sendMsg(QString string)
{
    QByteArray byteArray = string.toUtf8();
    m_clientSocket->write(byteArray);
}

