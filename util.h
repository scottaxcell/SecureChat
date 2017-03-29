#ifndef UTIL_H
#define UTIL_H

#include <QtCore>
#include <QTcpSocket>

// OpenSSL includes
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define PADDING RSA_PKCS1_PADDING
#define KEYSIZE 32
#define IVSIZE 32
#define SALTSIZE 8

#define FILEPKT 457
#define MSGPKT 557
#define PKTHEADERSIZE (sizeof(quint32) + sizeof(quint16))

/*
 * quint32 pktSize;
 * quint16 pktType;
 * QByeArray pktData;
 */

struct IncomingPacket
{
    quint32 pktSize;
    quint16 pktType;
    QByteArray encryptedBuffer;
    quint32 bytesRead;
    bool displayedFileUpdate;

    IncomingPacket()
    {
        reset();
    }

    void reset()
    {
        pktSize = 0;
        pktType = 0;
        encryptedBuffer.clear();
        bytesRead = 0;
        displayedFileUpdate = false;
    }
};

class Util
{
public:
    Util();

    static QByteArray getRandomBytes(int size);

    static QByteArray rsaPublicEncrypt(RSA *rsa, QByteArray &data);
    static QByteArray rsaPrivateDecrypt(RSA *rsa, QByteArray &data);

    static QByteArray aesEncrypt(QByteArray &passphrase, QByteArray &data);
    static QByteArray aesDecrypt(QByteArray &passphrase, QByteArray &data);

    static void handleIncomingPacket(QTcpSocket *socket, IncomingPacket &icp);
};

#endif // UTIL_H
