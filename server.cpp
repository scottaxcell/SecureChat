#include "server.h"

#include <QtCore>
#include <QHostAddress>
#include <QNetworkInterface>

Server::Server(QObject *parent) :
    QTcpServer(parent)
{

}

Server::Server(quint16 port, QObject *parent) :
    QTcpServer(parent)
{
    m_clientSocket = nullptr;
    m_port = port;
    foreach (const QHostAddress &address, QNetworkInterface::allAddresses()) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol && address != QHostAddress(QHostAddress::LocalHost))
            m_ip = address.toString();
    }
    if (this->listen(QHostAddress(m_ip), m_port)) {
        qDebug() << "Server started listening on" << this->serverAddress() << ":" << this->serverPort();
    } else {
        qDebug() << "Server failed to start";
    }
}

void Server::initialize()
{
    //qDebug() << "Server listening on " << m_ip << ":" << m_port;
    if (this->listen(QHostAddress::Any, m_port)) {
    //if (this->listen(QHostAddress(m_ip), m_port)) {
        qDebug() << "Server started listening on" << this->serverAddress() << ":" << this->serverPort();
    } else {
        qDebug() << "Server failed to start";
    }
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

    m_clientSocket->write("Hello client, I'm the server!");

}

void Server::disconnected()
{
    qDebug() << "Server disconnected from client";
    m_clientSocket->deleteLater();
}

void Server::bytesWritten(qint64 bytes)
{
    qDebug() << "Client wrote" << bytes << "bytes";
}

void Server::readyRead()
{
    qDebug() << "Server read:";
    qDebug() << m_clientSocket->readAll();
}
