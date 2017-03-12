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

// The PADDING parameter means RSA will pad your data for you
//#define PADDING RSA_PKCS1_OAEP_PADDING
//#define PADDING RSA_PKCS1_PADDING
//#define PADDING RSA_NO_PADDING
#define PADDING RSA_PKCS1_PADDING
#define KEYSIZE 32
#define IVSIZE 32
#define SALTSIZE 8

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
