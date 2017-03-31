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
    m_icp = IncomingPacket();

    m_socket = new QTcpSocket(this);

    connect(m_socket, SIGNAL(bytesWritten(qint64)), this, SLOT(bytesWritten(qint64)));
    connect(m_socket, SIGNAL(connected()), this, SLOT(connected()));
    connect(m_socket, SIGNAL(disconnected()), this, SLOT(disconnected()));
    connect(m_socket, SIGNAL(readyRead()), this, SLOT(readyRead()));

    m_passphrase = Util::getRandomBytes(15);
}

void Client::connectToServer()
{
    QString msg = "INFO: Connecting to server at " + m_ip + ":" + QString::number(m_port) + " ...";
    emit statusUpdate(msg);
    qDebug() << "Client attempting to connect to" << m_ip << ":" << m_port;

    m_socket->connectToHost(QHostAddress(m_ip), m_port);
    if (!m_socket->waitForConnected(10000)) {
        QString msg = "INFO: Client failed to connect to server with error '" + m_socket->errorString() + "'";
        qDebug() << msg;
        emit statusUpdate(msg);
    }

}

void Client::connected()
{
    QHostAddress addr = m_socket->peerAddress();
    quint16 port = m_socket->peerPort();
    QString msg = "INFO: Connected to server at " + addr.toString() + ":" + QString::number(port);
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
    QString msg = "INFO: Server at " + addr.toString() + ":" + QString::number(port) + " disconnected";
    emit statusUpdate(msg);
}

void Client::bytesWritten(qint64 bytes)
{
    qDebug() << "Client wrote" << bytes << "bytes";
}

void Client::readyRead()
{
    Util::handleIncomingPacket(m_socket, m_icp);

    if (m_icp.pktType == FILEPKT && m_icp.displayedFileUpdate == false) {
        m_icp.displayedFileUpdate = true;
        QString msg = "INFO: Receiving file from friend, please wait ...";
        emit statusUpdate(msg);
    }

    if ((m_icp.bytesRead + PKTHEADERSIZE) == m_icp.pktSize) {
        // We have the entire message

        QByteArray decryptedBuffer = Util::aesDecrypt(m_passphrase, m_icp.encryptedBuffer);

        if (m_icp.pktType == MSGPKT) {
            emit msgReceived(decryptedBuffer);
        } else if (m_icp.pktType == FILEPKT) {

            quint32 fileNameSize;
            memcpy(&fileNameSize, &decryptedBuffer.data()[0], sizeof(fileNameSize));

            QByteArray tmp;
            tmp.fill(0, fileNameSize);
            memcpy(&tmp.data()[0], &decryptedBuffer.data()[4], fileNameSize);
            QString fileName = QTextCodec::codecForMib(106)->toUnicode(tmp);

            quint32 fileDataIndex = 4 + fileNameSize;
            QByteArray fileData;
            for (int i = fileDataIndex; i < decryptedBuffer.size(); i ++) {
                fileData.append(decryptedBuffer[i]);
            }

            QFile file(fileName);
            file.open(QFile::WriteOnly);
            file.write(fileData);
            file.close();
            QString msg = "INFO: Received and wrote file to " + fileName;
            emit statusUpdate(msg);
        } else {
            qCritical() << "ERROR: read wrong packet type";
            return;
        }

        // Reset the incoming packet information for the next packet
        m_icp.reset();
    }
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
    QString msg = "INFO: Reading " + fileName + " ...";
    emit statusUpdate(msg);

    QFile file(fileName);
    file.open(QFile::ReadOnly);
    QByteArray fileData = file.readAll();
    file.close();

    msg = "INFO: Read " + QString::number(fileData.size()) + " bytes from " + fileName;
    emit statusUpdate(msg);

    msg = "INFO: Sending file " + fileName + ", please wait ...";
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
    quint32 pktSize = sizeof(quint32) + sizeof(pktType) + encrypted.size();

    QByteArray pkt;
    pkt.resize(pktSize);
    memset(&pkt.data()[0], 0, pktSize);
    memcpy(&pkt.data()[0], &pktSize, sizeof(pktSize)); // 4
    memcpy(&pkt.data()[4], &pktType, sizeof(pktType)); // 2
    memcpy(&pkt.data()[6], &encrypted.data()[0], encrypted.size());

    m_socket->write(pkt);
    while (m_socket->bytesToWrite() > 0) {
        m_socket->waitForBytesWritten(10000);
    }
    msg = "INFO: Completed sending file " + fileName + " to friend";
    emit statusUpdate(msg);
}
