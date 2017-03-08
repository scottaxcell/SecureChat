#include "util.h"

#include <QFile>

Util::Util()
{

}

//static RSA *getPublicKey(QByteArray &data)
//{
//    const char* keyStr = data.constData();
//    BIO* bio = BIO_new_mem_buf((void*)keyStr, -1);
//    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

//    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
//    if (!rsa) {
//        qCritical() << "ERROR: cound not load public key";
//        return nullptr;
//    }

//    BIO_free(bio);
//    return rsa;
//}

//static RSA *getPublicKey(QString fileName)
//{
//    QByteArray data = Util::readPEMFile(fileName);
//    return getPublicKey(data);
//}

//static QByteArray readPEMFile(QString fileName)
//{
//    QByteArray data;
//    QFile file(fileName);
//    if (!file.open(QFile::ReadOnly)) {
//        qCritical() << "ERROR: unable to open PEM file" << file.errorString();
//        return data;
//    }

//    data = file.readAll();
//    file.close();
//    return data;
//}

//static RSA *getPrivateKey(QByteArray &data)
//{
//    const char* keyStr = data.constData();
//    BIO* bio = BIO_new_mem_buf((void*)keyStr, -1);
//    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

//    RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
//    if (!rsa) {
//        qCritical() << "ERROR: cound not load private key";
//        return nullptr;
//    }

//    BIO_free(bio);
//    return rsa;
//}

//static RSA *getPrivateKey(QString fileName)
//{
//    QByteArray data = readPEMFile(fileName);
//    return getPrivateKey(data);
//}

//static QByteArray encryptData(RSA *rsa, QByteArray &data)
//{
//    QByteArray buffer;
//    int dataSize = data.length();
//    const unsigned char *from = (const unsigned char*)data.constData();
//    int rsaSize = RSA_size(rsa);
//    unsigned char *to = (unsigned char*)malloc(rsaSize);
//    int rv = RSA_public_encrypt(dataSize, (const unsigned char*)from, to, rsa, PADDING);
//    if (rv == -1) {
//        qCritical() << "ERROR: could not encrypt data with public key" << ERR_error_string(ERR_get_error(), nullptr);
//        return buffer;
//    }

//    buffer = QByteArray(reinterpret_cast<char*>(to), rv);
//    return buffer;
//}

//static QByteArray decryptData(RSA *rsa, QByteArray &data)
//{
//    QByteArray buffer;
//    return buffer;
//}



