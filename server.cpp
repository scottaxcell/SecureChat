#include "server.h"
#include "util.h"

#include <QtCore>
#include <QHostAddress>
#include <QNetworkInterface>

Server::Server(RSA *pubRSA, RSA *privRSA, QObject *parent) :
    QTcpServer(parent)
{
    m_pubRSA = pubRSA;
    m_privRSA = privRSA;
    m_socket = nullptr;
    m_useAES = false;
    m_icp = IncomingPacket();
}

void Server::initialize(QThread &t)
{
    connect(&t, SIGNAL(started()), this, SLOT(run()));
}

void Server::incomingConnection(qintptr handle)
{
    qDebug() << "Server has incoming client connection";
    m_socket = new QTcpSocket();
    if (!m_socket->setSocketDescriptor(handle)) {
        qDebug() << m_socket->errorString();
        return;
    }

    connect(m_socket, SIGNAL(bytesWritten(qint64)), this, SLOT(bytesWritten(qint64)), Qt::DirectConnection);
    connect(m_socket, SIGNAL(disconnected()), this, SLOT(disconnected()), Qt::DirectConnection);
    connect(m_socket, SIGNAL(readyRead()), this, SLOT(readyRead()), Qt::DirectConnection);

    qDebug() << "Server has connected with client successfully";

    QHostAddress addr = m_socket->peerAddress();
    quint16 port = m_socket->peerPort();
    QString msg = "INFO: Connected to client at " + addr.toString() + ":" + QString::number(port);
    emit statusUpdate(msg);
}

void Server::disconnected()
{
    qDebug() << "Server disconnected from client";
    QHostAddress addr = m_socket->peerAddress();
    quint16 port = m_socket->peerPort();
    QString msg = "INFO: Client at " + addr.toString() + ":" + QString::number(port) + " disconnected";
    emit statusUpdate(msg);
    m_useAES = false;
    m_socket->deleteLater();
}

void Server::bytesWritten(qint64 bytes)
{
    qDebug() << "Client wrote" << bytes << "bytes";
}

void Server::readyRead()
{
    qDebug() << "Server readyRead TODO";

    if (!m_useAES) {
        // First thing client sends is the AES passphrase via RSA
        QByteArray encrypted = m_socket->readAll();
        QByteArray decrypted = Util::rsaPrivateDecrypt(m_privRSA, encrypted);
        m_passphrase = decrypted;
        qDebug() << "passphrase:" << m_passphrase;
        m_useAES = true;
        QString msg = "INFO: Received AES passphrase from client, all further communication is encrpyted using AES";
        emit statusUpdate(msg);
        return;
    }

    Util::handleIncomingPacket(m_socket, m_icp);

    if (m_icp.pktType == FILEPKT && m_icp.displayedFileUpdate == false) {
        m_icp.displayedFileUpdate = true;
        QString msg = "INFO: Receiving file from friend, please wait ...";
        emit statusUpdate(msg);
    }

    if ((m_icp.bytesRead + PKTHEADERSIZE) == m_icp.pktSize) {
        // We have the entire message
        qDebug() << "Received the entire packet of" << m_icp.pktSize << "bytes";
        QString blah = QString(QCryptographicHash::hash(m_icp.encryptedBuffer,QCryptographicHash::Md5).toHex());
        qDebug() << "encrypted md5:" << blah;

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
            qDebug() << "pkt minus header size:" << decryptedBuffer.size();
            qDebug() << "fileNameSize:" << fileNameSize;
            qDebug() << "fileName:" << fileName;
            qDebug() << "fileData.size:" << fileData.size();

            //                QString msg = "Successfully received file " + fileName + " from friend";
            //                emit statusUpdate(msg);
            QFile file(fileName);
            file.open(QFile::WriteOnly);
            file.write(fileData);
            file.close();
            QString msg = "INFO: Received and wrote file to " + fileName;
            emit statusUpdate(msg);

            QFile f("server.encrypted");
            f.open(QFile::WriteOnly);
            f.write(m_icp.encryptedBuffer);
            f.close();

        } else {
            qCritical() << "ERROR: read wrong packet type";
            return;
        }

        // Reset the incoming packet information for the next packet
        m_icp.reset();
    }
}

void Server::run()
{
    QHostAddress ip;
    foreach (const QHostAddress &address, QNetworkInterface::allAddresses()) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol && address != QHostAddress(QHostAddress::LocalHost))
            ip = address;
    }
    if (this->listen(ip, 0)) {
        QString msg = "INFO: Listening for a client connection on " + ip.toString() + ":" + QString::number(this->serverPort());
        qDebug() << msg;
        emit statusUpdate(msg);
    } else {
        qDebug() << "Server failed to start";
    }
}

void Server::sendMsg(QString string)
{
    qDebug() << "Server sendMsg TODO";
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

void Server::sendFile(QString fileName)
{
    qDebug() << "Server sendFile TODO";
    QString msg = "INFO: Reading " + fileName + " ...";
    emit statusUpdate(msg);

    QFile file(fileName);
    file.open(QFile::ReadOnly);
    QByteArray fileData = file.readAll();
    file.close();

    msg = "INFO: Read " + QString::number(fileData.size()) + " bytes from " + fileName;
    emit statusUpdate(msg);

    msg = "INFO: Sending file " + fileName + ", please wait...";
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

    qDebug() << "pktSize:" << pktSize;
    qDebug() << "pktType:" << pktType;
    qDebug() << "fileNameSize:" << fileNameSize;
    qDebug() << "fileName:" << fileName;
    qDebug() << "fileData.size:" << fileSize;

    qint64 numBytesSent = pktSize;
    while (numBytesSent > 0) {
        numBytesSent -= m_socket->write(pkt);
    }

    msg = "INFO: Completed sending file " + fileName + " to friend";
    emit statusUpdate(msg);
}
