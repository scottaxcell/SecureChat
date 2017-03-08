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
#define BLOCKSIZE 256
#define SALTSIZE 8

class Util
{
public:
    Util();

//    static RSA *getPublicKey(QByteArray &data);
//    static RSA *getPublicKey(QString fileName);
//    static QByteArray readPEMFile(QString fileName);

//    static RSA *getPrivateKey(QByteArray &data);
//    static RSA *getPrivateKey(QString fileName);

//    static QByteArray encryptData(RSA *rsa, QByteArray &data);
//    static QByteArray decryptData(RSA *rsa, QByteArray &data);
};

#endif // UTIL_H
