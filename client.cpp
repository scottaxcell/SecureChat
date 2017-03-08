#include "client.h"

#include <QtCore>
#include <QHostAddress>

Client::Client(QObject *parent) : QObject(parent)
{

}

Client::Client(QString ip, quint16 port, RSA *pubRSA, RSA *privRSA, QObject *parent) :
    QObject(parent)
{
    m_ip = ip;
    m_port = port;
    m_pubRSA = pubRSA;
    m_privRSA = privRSA;

    m_socket = new QTcpSocket(this);

    connect(m_socket, SIGNAL(bytesWritten(qint64)), this, SLOT(bytesWritten(qint64)));
    connect(m_socket, SIGNAL(connected()), this, SLOT(connected()));
    connect(m_socket, SIGNAL(disconnected()), this, SLOT(disconnected()));
    connect(m_socket, SIGNAL(readyRead()), this, SLOT(readyRead()));
}

void Client::connectToServer()
{
    QString msg = "Connecting to server at " + m_ip + ":" + QString::number(m_port) + "...";
    emit statusUpdate(msg);
    qDebug() << "Client attempting to connect to" << m_ip << ":" << m_port;

    m_socket->connectToHost(QHostAddress(m_ip), m_port);
    if (!m_socket->waitForConnected(10000)) {
        QString msg = "Client failed to connect to server with error '" + m_socket->errorString() + "'";
        qDebug() << msg;
        emit statusUpdate(msg);
    }

}

void Client::connected()
{
    QHostAddress addr = m_socket->peerAddress();
    quint16 port = m_socket->peerPort();
    QString msg = "Connected to server at " + addr.toString() + ":" + QString::number(port) + " successfully";
    emit statusUpdate(msg);

    qDebug() << "Client connected to server";

    // Send first message to server
    //m_socket->write("Hola server, I'm the client!");

    // TODO encrypt AES key
    // TODO send encrypted AES key (prepend msgType == AES to msg)
    //m_clientSocket->write("Hello client, I'm the server!");
}

void Client::disconnected()
{
    qDebug() << "Client disconnected from server";
    QHostAddress addr = m_socket->peerAddress();
    quint16 port = m_socket->peerPort();
    QString msg = "Server at " + addr.toString() + ":" + QString::number(port) + " disconnected";
    emit statusUpdate(msg);
}

void Client::bytesWritten(qint64 bytes)
{
    qDebug() << "Client wrote" << bytes << "bytes";
}

void Client::readyRead()
{
    qDebug() << "Client read:";
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

QByteArray Client::encryptData(RSA *rsa, QByteArray &data)
{
    QByteArray buffer;
    int dataSize = data.length();
    const unsigned char *from = (const unsigned char*)data.constData();
    int rsaSize = RSA_size(rsa);
    unsigned char *to = (unsigned char*)malloc(rsaSize);
    int rv = RSA_public_encrypt(dataSize, (const unsigned char*)from, to, rsa, PADDING);
    if (rv == -1) {
        qCritical() << "ERROR: could not encrypt data with public key" << ERR_error_string(ERR_get_error(), nullptr);
        return buffer;
    }

    buffer = QByteArray(reinterpret_cast<char*>(to), rv);
    return buffer;
}

QByteArray Client::decryptData(RSA *rsa, QByteArray &data)
{
    QByteArray buffer;
    const unsigned char *from = (const unsigned char*)data.constData();
    int rsaSize = RSA_size(rsa);
    unsigned char *to = (unsigned char*)malloc(rsaSize);
    int rv = RSA_private_decrypt(rsaSize, from, to, rsa, PADDING);
    if (rv == -1) {
        qCritical() << "ERROR: could not dencrypt data with private key" << ERR_error_string(ERR_get_error(), nullptr);
        return buffer;
    }

    buffer = QByteArray::fromRawData((const char*)to, rv);
    return buffer;
}
