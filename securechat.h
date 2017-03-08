#ifndef SECURECHAT_H
#define SECURECHAT_H

#include <QMainWindow>

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

namespace Ui {
class SecureChat;
}

class SecureChat : public QMainWindow
{
    Q_OBJECT

public:
    explicit SecureChat(QWidget *parent = 0);
    explicit SecureChat(int argc, char **argv, QWidget *parent = 0);
    explicit SecureChat(QStringList args, QWidget *parent = 0);
    ~SecureChat();

protected:
    bool eventFilter(QObject *obj, QEvent *ev);

signals:
    // Notifies a thread that the user has input a message to send
    void msgInput(QString);

public slots:
    // Writes to the textBrowser when notified by a thread
    void updateLog(QByteArray);
    void updateLog(QString);

private:
    Ui::SecureChat *ui;

    RSA *getPublicKey(QByteArray &data);
    RSA *getPublicKey(QString fileName);
    QByteArray readPEMFile(QString fileName);

    RSA *getPrivateKey(QByteArray &data);
    RSA *getPrivateKey(QString fileName);

    QByteArray encryptData(RSA *rsa, QByteArray &data);
    QByteArray decryptData(RSA *rsa, QByteArray &data);
};

#endif // SECURECHAT_H
