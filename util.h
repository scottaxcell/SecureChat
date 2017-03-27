#ifndef UTIL_H
#define UTIL_H

#include <QtCore>

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

class Util
{
public:
    Util();

    static QByteArray getRandomBytes(int size);

    static QByteArray rsaPublicEncrypt(RSA *rsa, QByteArray &data);
    static QByteArray rsaPrivateDecrypt(RSA *rsa, QByteArray &data);

    static QByteArray aesEncrypt(QByteArray &passphrase, QByteArray &data);
    static QByteArray aesDecrypt(QByteArray &passphrase, QByteArray &data);

};

#endif // UTIL_H
