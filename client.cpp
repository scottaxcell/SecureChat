#include "client.h"

#include <QtCore>
#include <QHostAddress>

Client::Client(QObject *parent) : QObject(parent)
{

}

Client::Client(QString ip, quint16 port, QObject *parent) :
    QObject(parent)
{
    m_ip = ip;
    m_port = port;

    m_socket = new QTcpSocket(this);

    connect(m_socket, SIGNAL(bytesWritten(qint64)), this, SLOT(bytesWritten(qint64)));
    connect(m_socket, SIGNAL(connected()), this, SLOT(connected()));
    connect(m_socket, SIGNAL(disconnected()), this, SLOT(disconnected()));
    connect(m_socket, SIGNAL(readyRead()), this, SLOT(readyRead()));
}

void Client::connectToServer()
{
    qDebug() << "Client attempting to connect to" << m_ip << ":" << m_port;

    m_socket->connectToHost(QHostAddress(m_ip), m_port);
    if (!m_socket->waitForConnected()) {
        qDebug() << "Client waitForConnected faile with error '" << m_socket->errorString() << "'";
    }

}

void Client::connected()
{
    qDebug() << "Client connected to server";

    // Send first message to server
    m_socket->write("Hola server, I'm the client!");
}

void Client::disconnected()
{
    qDebug() << "Client disconnected from server";
}

void Client::bytesWritten(qint64 bytes)
{
    qDebug() << "Client wrote" << bytes << "bytes";
}

void Client::readyRead()
{
    qDebug() << "Client read:";
    //qDebug() << m_socket->readAll();
    emit msgReceived(m_socket->readAll());
}

void Client::run()
{
    connectToServer();
}

void Client::initialize(QThread &t)
{
    connect(&t, SIGNAL(started()), this, SLOT(run()));
}

void Client::sendMsg(QString string)
{
    QByteArray byteArray = string.toUtf8();
    m_socket->write(byteArray);
}

