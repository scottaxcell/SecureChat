#include "securechat.h"
#include "ui_securechat.h"

#include <QKeyEvent>
#include <QThread>
#include <QTextCodec>
#include <QCommandLineParser>
#include <QFileInfo>

#include "server.h"
#include "client.h"
#include "util.h"

#include <iostream>

namespace {
bool fileExists(QString path) {
    QFileInfo check_file(path);
    // check if file exists and if yes: Is it really a file and no directory?
    if (check_file.exists() && check_file.isFile()) {
        return true;
    } else {
        return false;
    }
}
}
SecureChat::SecureChat(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::SecureChat)
{
    ui->setupUi(this);
}

SecureChat::~SecureChat()
{
    // OpenSSL cleanup
    EVP_cleanup();
    ERR_free_strings();

    delete ui;
}

SecureChat::SecureChat(QStringList args, QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::SecureChat)
{
    // UI setup
    ui->setupUi(this);
    ui->lineEdit->installEventFilter(this);
    connect(ui->sendMsgButton, SIGNAL(clicked()), this, SLOT(sendButtonClicked()));

    // Parse the command line arguments
    QCommandLineParser parser;
    parser.setApplicationDescription("Secure Chat Server/Client");
    parser.addHelpOption();
    parser.addVersionOption();

    parser.addPositionalArgument("<public file>", QCoreApplication::translate("main", "Public key PEM file"));
    parser.addPositionalArgument("<private file>", QCoreApplication::translate("main", "Private key PEM file"));

    QCommandLineOption portOption("p", "Server port to connect to.", "port");
    parser.addOption(portOption);

    QCommandLineOption ipOption("i", "Server IP address to connect to", "ip");
    parser.addOption(ipOption);

    parser.process(args);
    qDebug() << args;

    const QStringList positionals = parser.positionalArguments();
    if (positionals.size() < 2) {
        qCritical() << "ERROR: Public PEM and private PEM files required, use -h for help";
        exit(1);
    }
    QString pubFile = positionals.at(0);
    if (!fileExists(pubFile)) {
        qCritical() << "ERROR: Public PEM does not exist" << pubFile;
        exit(1);
    }
    QString privFile = positionals.at(1);
    if (!fileExists(privFile)) {
        qCritical() << "ERROR: Private PEM does not exist" << privFile;
        exit(1);
    }

    // Initialize OpenSSL algorithms
    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(nullptr);

    RSA *pubRSA = getPublicKey(pubFile); // Leaks memory, 256 bytes is minimal.
    RSA *privRSA = getPrivateKey(privFile); // Leaks memory, 256 bytes is minimal.

    if (parser.isSet(ipOption) || parser.isSet(portOption)) {
        //
        // Run a client
        //
        if (parser.isSet(ipOption) && !parser.isSet(portOption)) {
            qCritical() << "ERROR: Missing server port argument, -p";
            exit(1);
        }
        if (!parser.isSet(ipOption) && parser.isSet(portOption)) {
            qCritical() << "ERROR: Missing server ip address argument, -i";
            exit(1);
        }
        QString ip = parser.value(ipOption);
        QString p = parser.value(portOption);
        quint16 port = parser.value(portOption).toUShort();
        Client *client = new Client(ip, port, pubRSA, privRSA);

        connect(this, SIGNAL(msgInput(QString)), client, SLOT(sendMsg(QString)));
        connect(client, SIGNAL(msgReceived(QByteArray)), this, SLOT(updateLog(QByteArray)));
        connect(client, SIGNAL(statusUpdate(QString)), this, SLOT(updateLog(QString)));

        QThread *t = new QThread();
        client->initialize(*t);
        client->moveToThread(t);
        t->start();
    } else {
        //
        // Run a server
        //
        Server *server = new Server(pubRSA, privRSA);

        connect(this, SIGNAL(msgInput(QString)), server, SLOT(sendMsg(QString)));
        connect(server, SIGNAL(msgReceived(QByteArray)), this, SLOT(updateLog(QByteArray)));
        connect(server, SIGNAL(statusUpdate(QString)), this, SLOT(updateLog(QString)));

        QThread *t = new QThread();
        server->initialize(*t);
        server->moveToThread(t);
        t->start();
    }
}

void SecureChat::sendButtonClicked()
{
    QString msg = ui->lineEdit->text();
    if (msg.size()) {
        emit msgInput(msg);
        ui->textBrowser->append("You: " + msg);
        ui->lineEdit->clear();
    }
}

bool SecureChat::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == ui->lineEdit) {
        if (event->type() == QEvent::KeyPress) {
            QKeyEvent *keyEvent = static_cast<QKeyEvent*>(event);
            if (keyEvent->key() == Qt::Key_Return) {
                QString msg = ui->lineEdit->text();
                if (msg.size()) {
                    emit msgInput(msg);
                    ui->textBrowser->append("You: " + msg);
                    ui->lineEdit->clear();
                }
            }
        }
        return QMainWindow::eventFilter(obj, event);
    } else {
        // pass the event on to the parent class
        return QMainWindow::eventFilter(obj, event);
    }
}

void SecureChat::updateLog(QByteArray bytes)
{
    QString string = "Friend: ";
    string += QTextCodec::codecForMib(106)->toUnicode(bytes);
    ui->textBrowser->append(string);
}

void SecureChat::updateLog(QString string)
{
    ui->textBrowser->append(string);
}

RSA *SecureChat::getPublicKey(QByteArray &data)
{
    const char* keyStr = data.constData();
    BIO* bio = BIO_new_mem_buf((void*)keyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!rsa) {
        qCritical() << "ERROR: cound not load public key";
        return nullptr;
    }

    BIO_free(bio);
    return rsa;
}

RSA *SecureChat::getPublicKey(QString fileName)
{
    QByteArray data = readPEMFile(fileName);
    return getPublicKey(data);
}

QByteArray SecureChat::readPEMFile(QString fileName)
{
    QByteArray data;
    QFile file(fileName);
    if (!file.open(QFile::ReadOnly)) {
        qCritical() << "ERROR: unable to open PEM file" << file.errorString();
        return data;
    }

    data = file.readAll();
    file.close();
    return data;
}

RSA *SecureChat::getPrivateKey(QByteArray &data)
{
    const char* keyStr = data.constData();
    BIO* bio = BIO_new_mem_buf((void*)keyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    if (!rsa) {
        qCritical() << "ERROR: cound not load private key";
        return nullptr;
    }

    BIO_free(bio);
    return rsa;
}

RSA *SecureChat::getPrivateKey(QString fileName)
{
    QByteArray data = readPEMFile(fileName);
    return getPrivateKey(data);
}

QByteArray SecureChat::encryptData(RSA *rsa, QByteArray &data)
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

QByteArray SecureChat::decryptData(RSA *rsa, QByteArray &data)
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
