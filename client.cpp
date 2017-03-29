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
    m_socket = nullptr;
    m_icp = IncomingPacket();

//    m_socket = new QTcpSocket(this);

//    connect(m_socket, SIGNAL(bytesWritten(qint64)), this, SLOT(bytesWritten(qint64)));
//    connect(m_socket, SIGNAL(connected()), this, SLOT(connected()));
//    connect(m_socket, SIGNAL(disconnected()), this, SLOT(disconnected()));
//    connect(m_socket, SIGNAL(readyRead()), this, SLOT(readyRead()));

    m_passphrase = "p@ssw0rd";
//    m_passphrase = Util::getRandomBytes(15);
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
    qDebug() << "Client readReady TODO";
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
            QString msg = "INFO: Receiving file from friend, please wait ...";
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
        qDebug() << "decryptedBuffer.size:" << decryptedBuffer.size();

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
            QByteArray fileData;
            for (int i = fileDataIndex; i < decryptedBuffer.size(); i ++) {
                fileData.append(decryptedBuffer[i]);
            }
            qDebug() << "pkt minus header size:" << decryptedBuffer.size();
            qDebug() << "fileNameSize:" << fileNameSize;
            qDebug() << "fileName:" << fileName;
            qDebug() << "fileData.size:" << fileData.size();

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
    }
}

void Client::run()
{
    m_socket = new QTcpSocket(this);

    connect(m_socket, SIGNAL(bytesWritten(qint64)), this, SLOT(bytesWritten(qint64)));
    connect(m_socket, SIGNAL(connected()), this, SLOT(connected()));
    connect(m_socket, SIGNAL(disconnected()), this, SLOT(disconnected()));
    connect(m_socket, SIGNAL(readyRead()), this, SLOT(readyRead()));

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
    QString blah = QString(QCryptographicHash::hash(encrypted,QCryptographicHash::Md5).toHex());
    qDebug() << "encrypted md5:" << blah;
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
    QString msg = "INFO: Reading " + fileName + "...";
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
    QString blah = QString(QCryptographicHash::hash(encrypted,QCryptographicHash::Md5).toHex());
    qDebug() << "encrypted md5:" << blah;
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

    m_socket->write(pkt);
    while (m_socket->bytesToWrite() > 0) {
        m_socket->waitForBytesWritten(10000);
    }
/*    int pktChunkSize = 100;
    for (int i = 0; i < (pktSize / pktChunkSize); i++) {
        qint64 bytesWritten = 0;
        while (bytesWritten < pktChunkSize) {
            qint64 wrote = m_socket->write(&pkt.constData()[bytesWritten], pktChunkSize);
            m_socket->flush();
            if (m_socket->bytesToWrite() > 0) {
                m_socket->waitForBytesWritten(10000);
            }
            if (wrote == -1) {
                qCritical() << "ERROR: could not write all of file pkt to socket";
                return;
            }
            qDebug() << "Wrote" << wrote << "bytes to the socket";

            bytesWritten += wrote;
            QThread::msleep(200);
            qDebug() << "Total bytes wrote" << i << ":" << bytesWritten << "of" << pktSize;
        }
    }
    if (pktSize % pktChunkSize) {
        qint64 bytesWritten = 0;
        while (bytesWritten < (pktSize % pktChunkSize)) {
            qint64 wrote = m_socket->write(&pkt.constData()[bytesWritten], (pktSize % pktChunkSize));
            m_socket->flush();
            if (m_socket->bytesToWrite() > 0) {
                m_socket->waitForBytesWritten(10000);
            }
            if (wrote == -1) {
                qCritical() << "ERROR: could not write all of file pkt to socket";
                return;
            }
            qDebug() << "% Wrote" << wrote << "bytes to the socket";
            bytesWritten += wrote;
            qDebug() << "% Total bytes wrote" << ":" << bytesWritten << "of" << pktSize;
        }
    }
*/
    QFile f("client.encrypted");
    f.open(QFile::WriteOnly);
    f.write(encrypted);
    f.close();


    msg = "INFO: Completed sending file " + fileName + " to friend";
    emit statusUpdate(msg);
}
