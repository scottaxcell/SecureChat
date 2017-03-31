#include "util.h"

#include <QFile>

Util::Util()
{

}

void Util::handleIncomingPacket(QTcpSocket *socket, IncomingPacket &icp)
{
    if (icp.pktType == 0) {
        // This is the first packet in the stream
        QByteArray buffer = socket->read(PKTHEADERSIZE);
        memcpy(&icp.pktSize, &buffer.constData()[0], sizeof(icp.pktSize));
        memcpy(&icp.pktType, &buffer.constData()[4], sizeof(icp.pktType));
        buffer.clear();
        icp.encryptedBuffer.resize(icp.pktSize - PKTHEADERSIZE);
    }

    while (socket->bytesAvailable()) {
        qint64 read = socket->read(&icp.encryptedBuffer.data()[icp.bytesRead], 1200);
        if (read == -1) {
            qCritical() << "ERROR: could not read entire packet";
            return;
        }
        icp.bytesRead += read;
    }
    qDebug() << "Total bytes read:" << icp.bytesRead;
}

QByteArray Util::getRandomBytes(int size)
{
    unsigned char arr[size];
    RAND_bytes(arr,size);

    QByteArray buffer = QByteArray(reinterpret_cast<char*>(arr), size);
    return buffer;
}

QByteArray Util::rsaPublicEncrypt(RSA *rsa, QByteArray &data)
{
    QByteArray buffer;
    int dataSize = data.length();
    const unsigned char *from = (const unsigned char*)data.constData();
    int rsaSize = RSA_size(rsa);
    unsigned char *to = (unsigned char*)malloc(rsaSize);
    int rv = RSA_public_encrypt(dataSize, (const unsigned char*)from, to, rsa, PADDING);
    if (rv == -1) {
        qCritical() << "ERROR: could not encrypt data with public key" << ERR_error_string(ERR_get_error(), nullptr);
        return buffer;
    }

    buffer = QByteArray(reinterpret_cast<char*>(to), rv);
    return buffer;
}

QByteArray Util::rsaPrivateDecrypt(RSA *rsa, QByteArray &data)
{
    QByteArray buffer;
    const unsigned char *from = (const unsigned char*)data.constData();
    int rsaSize = RSA_size(rsa);
    unsigned char *to = (unsigned char*)malloc(rsaSize);
    int rv = RSA_private_decrypt(rsaSize, from, to, rsa, PADDING);
    if (rv == -1) {
        qCritical() << "ERROR: could not dencrypt data with private key" << ERR_error_string(ERR_get_error(), nullptr);
        return buffer;
    }

    buffer = QByteArray::fromRawData((const char*)to, rv);
    return buffer;
}

QByteArray Util::aesEncrypt(QByteArray &passphrase, QByteArray &data)
{
    QByteArray saltArray = getRandomBytes(SALTSIZE);
    int rounds = 1;
    unsigned char key[KEYSIZE];
    unsigned char iv[IVSIZE];

    const unsigned char* salt = (const unsigned char*)saltArray.constData();
    const unsigned char* passwd = (const unsigned char*)passphrase.constData();

    int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, passwd, passphrase.size(), rounds, key, iv);

    if (i != KEYSIZE) {
        qCritical() << "EVP_BytesToKey() ERROR: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    if (!EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        qCritical() << "EVP_EncryptInit_ex() ERROR: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    char *input = data.data();
    int inputLength = data.size();
    unsigned char *output = (unsigned char*)malloc(inputLength + EVP_CIPHER_CTX_block_size(&ctx));

    int tmp = 0;
    int outputLength = 0;

    if (!EVP_EncryptUpdate(&ctx, &output[outputLength], &tmp, (unsigned char *)&input[outputLength], inputLength)) {
        qCritical() << "EVP_EncryptUpdate() ERROR: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }
    outputLength += tmp;


    if (!EVP_EncryptFinal_ex(&ctx, &output[outputLength], &tmp)) {
        qCritical() << "EVP_EncryptFinal_ex() ERROR: "  << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }
    outputLength += tmp;

    QByteArray encrypted = QByteArray(reinterpret_cast<char*>(output), outputLength);
    QByteArray ret;
    ret.append("Salted__");
    ret.append(saltArray);
    ret.append(encrypted);

    free(output);
    EVP_CIPHER_CTX_cleanup(&ctx);

    return ret;
}

QByteArray Util::aesDecrypt(QByteArray &passphrase, QByteArray &data)
{
    QByteArray saltArray;
    if (QString(data.mid(0,8)) == "Salted__") {
        saltArray = data.mid(8,8);
        data = data.mid(16);
    } else {
        qWarning() << "WARNING: no salt in data";
        saltArray = getRandomBytes(SALTSIZE);
    }

    int rounds = 1;
    unsigned char key[KEYSIZE];
    unsigned char iv[IVSIZE];
    const unsigned char* salt = (const unsigned char*)saltArray.constData();
    const unsigned char* passwd = (const unsigned char*)passphrase.data();

    int rc = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, passwd, passphrase.size(), rounds, key, iv);

    if (rc != KEYSIZE) {
        qCritical() << "EVP_BytesToKey() ERROR: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    if (!EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        qCritical() << "EVP_DecryptInit_ex() ERROR: " << ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }

    char *input = data.data();
    int inputLength = data.size();
    int outputLength = 0;

    unsigned char *output = (unsigned char *)malloc(inputLength + EVP_CIPHER_CTX_block_size(&ctx));

    int tmp = 0;
    if (!EVP_DecryptUpdate(&ctx, &output[outputLength], &tmp, (unsigned char *)&input[outputLength], inputLength)) {
        qCritical() << "EVP_DecryptUpdate() ERROR: " <<  ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }
    outputLength += tmp;

    if (!EVP_DecryptFinal_ex(&ctx, &output[outputLength], &tmp)) {
        qCritical() << "EVP_DecryptFinal_ex() ERROR: " <<  ERR_error_string(ERR_get_error(), nullptr);
        return QByteArray();
    }
    outputLength += tmp;

    EVP_CIPHER_CTX_cleanup(&ctx);

    QByteArray decrypted = QByteArray(reinterpret_cast<char*>(output), outputLength);
    free(output);

    return decrypted;
}
