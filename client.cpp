#include "client.h"
#include "util.h"

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

    // TODO create AES passphrase
    m_passphrase = "p@ssw0rd";
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

    //    QByteArray plain = "The man in black fled into the desert and the gunslinger followed...";
    //    QByteArray encrypted = Util::rsaPublicEncrypt(m_pubRSA, plain);
    //    m_socket->write(encrypted);

    QByteArray encrypted = Util::rsaPublicEncrypt(m_pubRSA, m_passphrase);
    m_socket->write(encrypted);
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
    QByteArray received = m_socket->readAll();
    QByteArray decrypted = Util::aesDecrypt(m_passphrase, received);
    emit msgReceived(decrypted);
    //emit msgReceived(m_socket->readAll());
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

    // Encrypt with AES
    QByteArray encrypted = Util::aesEncrypt(m_passphrase, byteArray);

    // Write to socket
    m_socket->write(encrypted);
}





