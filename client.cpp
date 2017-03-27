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

    qDebug() << "Client connected";
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
    qDebug() << "Client readReady TODO";
    QByteArray buffer;
    while (m_socket->bytesAvailable() > 0) {
        buffer.append(m_socket->readAll());
        quint32 pktSize;

    }
    //    QByteArray received = m_socket->readAll();
    //    QByteArray decrypted = Util::aesDecrypt(m_passphrase, received);
    //    emit msgReceived(decrypted);
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
    qDebug() << "Client sendMsg TODO";
    QByteArray msgArray = string.toUtf8();
    quint16 pktType = MSGPKT;

    // Encrypt msg with AES before sending pkt
    QByteArray encrypted = Util::aesEncrypt(m_passphrase, msgArray);
    quint32 msgSize = encrypted.size();
    quint32 pktSize = sizeof(quint32) + sizeof(pktType) + msgSize;

    QByteArray pkt;
    pkt.resize(pktSize);
    memset(&pkt.data()[0], 0, pktSize);
    memcpy(&pkt.data()[0], &pktSize, sizeof(pktSize));
    memcpy(&pkt.data()[4], &pktType, sizeof(pktType));
    memcpy(&pkt.data()[6], &encrypted.data()[0], msgSize);

    qint64 numBytesSent = pktSize;
    while (numBytesSent > 0) {
        numBytesSent -= m_socket->write(pkt);
    }
}

void Client::sendFile(QString fileName)
{
    qDebug() << "Server sendFile TODO encryption";
    QString msg = "Reading " + fileName + "...";
    emit statusUpdate(msg);

    QFile file(fileName);
    file.open(QFile::ReadOnly);
    QByteArray fileData = file.readAll();
    file.close();

    msg = "Read " + QString::number(fileData.size()) + " bytes from " + fileName;
    emit statusUpdate(msg);

    msg = "Sending file " + fileName + ", please wait...";
    emit statusUpdate(msg);

    QStringList fileNameSplit = fileName.split('/');
    fileName = fileNameSplit.last();

    quint16 pktType = FILEPKT;
    quint32 fileNameSize = fileName.toUtf8().size();
    quint32 fileSize = fileData.size();

    quint32 tmpPktSize = sizeof(fileNameSize) + fileNameSize + fileSize;
    QByteArray tmpPkt;
    tmpPkt.resize(tmpPktSize);
    memset(&tmpPkt.data()[0], 0, tmpPktSize);
    memcpy(&tmpPkt.data()[0], &fileNameSize, sizeof(fileNameSize)); // 4
    memcpy(&tmpPkt.data()[4], &fileName.toUtf8().data()[0], fileNameSize); // 3
    memcpy(&tmpPkt.data()[4 + fileNameSize], &fileData.data()[0], fileSize); // N

    QByteArray encrypted = Util::aesEncrypt(m_passphrase, tmpPkt);

    //quint32 pktSize = sizeof(quint32) + sizeof(pktType) + sizeof(fileNameSize) + fileNameSize + encrypted.size();
    quint32 pktSize = sizeof(quint32) + sizeof(pktType) + encrypted.size();

    // pktSize
    // pktType
    // fileNameSize
    // fileName

    // quint32 pktSize = 4 + 2 + 4 + 3 + 196
    QByteArray pkt;
    pkt.resize(pktSize);
    memset(&pkt.data()[0], 0, pktSize);
    memcpy(&pkt.data()[0], &pktSize, sizeof(pktSize)); // 4
    memcpy(&pkt.data()[4], &pktType, sizeof(pktType)); // 2
    memcpy(&pkt.data()[6], &encrypted.data()[0], encrypted.size());
    //    memcpy(&pkt.data()[6], &fileNameSize, sizeof(fileNameSize)); // 4
    //    memcpy(&pkt.data()[10], &fileName.toUtf8().data()[0], fileNameSize); // 3
    //    memcpy(&pkt.data()[10 + fileNameSize], &fileData.data()[0], fileSize); // 196

    qDebug() << "pktSize:" << pktSize;
    qDebug() << "pktType:" << pktType;
    qDebug() << "fileNameSize:" << fileNameSize;
    qDebug() << "fileName:" << fileName;
    qDebug() << "fileData.size:" << fileSize;

    qint64 numBytesSent = pktSize;
    while (numBytesSent > 0) {
        numBytesSent -= m_socket->write(pkt);
    }

    // Encrypt with AES
    //TODOQByteArray encrypted = Util::aesEncrypt(m_passphrase, pkt);

    // Write to socket
    //m_socket->write(encrypted);

    // Send file contents now
    // TODO

    msg = "Successfully sent file " + fileName + " to friend";
    emit statusUpdate(msg);
}





