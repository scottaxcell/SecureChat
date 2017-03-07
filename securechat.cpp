#include "securechat.h"
#include "ui_securechat.h"

#include <QKeyEvent>
#include <QThread>
#include <QTextCodec>
#include <QCommandLineParser>
#include <QFileInfo>

#include "server.h"
#include "client.h"

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
    delete ui;
}

SecureChat::SecureChat(QStringList args, QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::SecureChat)
{
    // UI setup
    ui->setupUi(this);
    ui->lineEdit->installEventFilter(this);

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
        Client *client = new Client(ip, port);

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
        Server *server = new Server();

        connect(this, SIGNAL(msgInput(QString)), server, SLOT(sendMsg(QString)));
        connect(server, SIGNAL(msgReceived(QByteArray)), this, SLOT(updateLog(QByteArray)));
        connect(server, SIGNAL(statusUpdate(QString)), this, SLOT(updateLog(QString)));

        QThread *t = new QThread();
        server->initialize(*t);
        server->moveToThread(t);
        t->start();
    }




    //    if (argc != 2) {
    //        std::cerr << "USAGE: ./SecureChat [server] [client]";
    //        exit(1);
    //    }

    //    QString type(argv[1]);
    //    if (type == "server") {
    //        quint16 port = 61723;
    //        Server *server = new Server(port);

    //        connect(this, SIGNAL(msgInput(QString)), server, SLOT(sendMsg(QString)));
    //        connect(server, SIGNAL(msgReceived(QByteArray)), this, SLOT(updateLog(QByteArray)));
    //        connect(server, SIGNAL(updateLog(QString)), this, SLOT(updateLog(QString)));

    //        QThread *t = new QThread();
    //        server->initialize(*t);
    //        server->moveToThread(t);
    //        t->start();
    //    } else if (type == "client") {
    //        quint16 port = 61723;
    //        QString ip = "10.0.0.10";
    //        Client *client = new Client(ip, port);

    //        connect(this, SIGNAL(msgInput(QString)), client, SLOT(sendMsg(QString)));
    //        connect(client, SIGNAL(msgReceived(QByteArray)), this, SLOT(updateLog(QByteArray)));
    //        connect(client, SIGNAL(updateLog(QString)), this, SLOT(updateLog(QString)));

    //        QThread *t = new QThread();
    //        client->initialize(*t);
    //        client->moveToThread(t);
    //        t->start();
    //    }

    //    ui->lineEdit->installEventFilter(this);




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
