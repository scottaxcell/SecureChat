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
    QString msg = "Connected to client at " + addr.toString() + ":" + QString::number(port) + " successfully";
    emit statusUpdate(msg);
}

void Server::disconnected()
{
    qDebug() << "Server disconnected from client";
    QHostAddress addr = m_socket->peerAddress();
    quint16 port = m_socket->peerPort();
    QString msg = "Client at " + addr.toString() + ":" + QString::number(port) + " disconnected";
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

    if (m_useAES) {

        while (m_socket->bytesAvailable() > 0) {
            QByteArray buffer = m_socket->read(PKTHEADERSIZE);
            quint32 pktSize;
            quint16 pktType;
            memcpy(&pktSize, &buffer.data()[0], sizeof(pktSize));
            memcpy(&pktType, &buffer.data()[4], sizeof(pktType));
            qDebug() << "pktSize:" << pktSize;
            qDebug() << "pktType:" << pktType;
            buffer.clear();
            pktSize -= PKTHEADERSIZE;

            if (pktType == FILEPKT) {
                QString msg = "Receiving file from friend, please wait ...";
                emit statusUpdate(msg);
            }
            qDebug() << "pktSize before while loop:" << pktSize;

            QByteArray encryptedBuffer;

            while (pktSize > 0) {
                // TODO check error message of readAll
                encryptedBuffer.append(m_socket->readAll());
                pktSize -= encryptedBuffer.size();
            }
            qDebug() << "past while loop!";
            QByteArray decryptedBuffer = Util::aesDecrypt(m_passphrase, encryptedBuffer);

            if (pktType == MSGPKT) {
                emit msgReceived(decryptedBuffer);
            } else if (pktType == FILEPKT) {
                quint32 fileNameSize;
                memcpy(&fileNameSize, &decryptedBuffer.data()[0], sizeof(fileNameSize));

                QByteArray tmp;
                tmp.fill(0, fileNameSize);
                memcpy(&tmp.data()[0], &decryptedBuffer.data()[4], fileNameSize);
                QString fileName = QTextCodec::codecForMib(106)->toUnicode(tmp);

                quint32 fileDataIndex = 4 + fileNameSize;
                QByteArray fileData(&decryptedBuffer.data()[fileDataIndex]);
                qDebug() << "pkt minus header size:" << decryptedBuffer.size();
                qDebug() << "fileNameSize:" << fileNameSize;
                qDebug() << "fileName:" << fileName;
                qDebug() << "fileData.size:" << fileData.size();

                QString msg = "Successfully received file " + fileName + " from friend";
                emit statusUpdate(msg);
                QFile file(fileName);
                file.open(QFile::WriteOnly);
                file.write(fileData);
                file.close();
                msg = "Successfully wrote file to " + fileName;
                emit statusUpdate(msg);
            } else {
                qCritical() << "ERROR: read wrong packet type";
                return;
            }
        }
    } else {
        // First thing client sends is the AES passphrase
        QByteArray encrypted = m_socket->readAll();
        QByteArray decrypted = Util::rsaPrivateDecrypt(m_privRSA, encrypted);
        m_passphrase = decrypted;
        m_useAES = true;
        QString msg = "INFO: Received AES passphrase from client, all further communication is encrpyted using AES";
        emit statusUpdate(msg);
    }

    //    if (m_useAES) {
    //        QByteArray encrypted = m_socket->readAll();
    //        QByteArray decrypted = Util::aesDecrypt(m_passphrase, encrypted);
    //        emit msgReceived(decrypted);
    //    } else {
    //        // First thing client sends is the AES passphrase
    //        QByteArray encrypted = m_socket->readAll();
    //        QByteArray decrypted = Util::rsaPrivateDecrypt(m_privRSA, encrypted);
    //        m_passphrase = decrypted;
    //        m_useAES = true;
    //        QString msg = "Received AES passphrase from client, all further communication is encrpyted using AES";
    //        emit statusUpdate(msg);
    //    }
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
    qDebug() << "Server sendMsg TODO";
    //    QByteArray byteArray = string.toUtf8();
    //    m_socket->write(byteArray);

    QByteArray rawMsg = string.toUtf8();

    quint16 msgType = 123;
    quint32 rawMsgSize = rawMsg.size();
    quint32 pktSize = sizeof(quint32) + sizeof(msgType) + rawMsgSize;
    QByteArray pkt;
    pkt.resize(pktSize);
    memset(&pkt.data()[0], 0, pktSize);
    memcpy(&pkt.data()[0], &pktSize, sizeof(pktSize));
    memcpy(&pkt.data()[4], &msgType, sizeof(msgType));
    memcpy(&pkt.data()[6], &rawMsg.data()[0], rawMsgSize);

    // Encrypt with AES
    //QByteArray encrypted = Util::aesEncrypt(m_passphrase, pkt);

    // Write to socket
    //m_socket->write(encrypted);
}

void Server::sendFile(QString fileName)
{
    qDebug() << "Server sendFile TODO";
    QString msg = "Reading " + fileName + "...";
    emit statusUpdate(msg);

    QFile file(fileName);
    file.open(QFile::ReadOnly);
    QByteArray data = file.readAll();
    file.close();

    msg = "Read " + QString::number(data.size()) + " bytes from " + fileName;
    emit statusUpdate(msg);

    msg = "Sending file " + fileName + ", please wait...";
    emit statusUpdate(msg);

    // Identifier, 457|557, 2 bytes
    // Filename size, quint32, 4 bytes
    // File size, quint32, 4 bytes
    // Filename, N bytes

    // TODO truncated filename if full path

    quint16 msgType = 457;
    quint32 fileNameSize = fileName.toUtf8().size();
    quint32 fileSize = data.size();

    qDebug() << "msgType: " << msgType;
    qDebug() << "fileNameSize:" << fileNameSize;
    qDebug() << "fileSize:" << fileSize;
    qDebug() << "fileName:" << fileName;

    quint32 pktSize = sizeof(msgType) + sizeof(fileNameSize) + sizeof(fileSize) + fileNameSize;
    QByteArray pkt;
    pkt.resize(pktSize);
    memset(&pkt.data()[0], 0, pktSize);
    memcpy(&pkt.data()[0], &msgType, sizeof(msgType));
    memcpy(&pkt.data()[2], &fileNameSize, sizeof(fileNameSize));
    memcpy(&pkt.data()[6], &fileSize, sizeof(fileSize));
    memcpy(&pkt.data()[10], &fileName.toUtf8().data()[0], fileName.size());

    // Encrypt with AES
    //TODOQByteArray encrypted = Util::aesEncrypt(m_passphrase, pkt);

    // Write to socket
    //m_socket->write(encrypted);

    // Send file contents now
    // TODO

    msg = "Successfully sent file " + fileName + " to friend";
    emit statusUpdate(msg);
}























