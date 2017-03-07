#include "securechat.h"
#include "ui_securechat.h"

#include <QKeyEvent>
#include <QThread>
#include <QTextCodec>

#include "server.h"
#include "client.h"

#include <iostream>

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

SecureChat::SecureChat(int argc, char **argv, QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::SecureChat)
{
    ui->setupUi(this);

    if (argc != 2) {
        std::cerr << "USAGE: ./SecureChat [server] [client]";
        exit(1);
    }

    QString type(argv[1]);
    if (type == "server") {
        quint16 port = 61723;
        Server *server = new Server(port);

        connect(this, SIGNAL(msgInput(QString)), server, SLOT(sendMsg(QString)));
        connect(server, SIGNAL(msgReceived(QByteArray)), this, SLOT(updateLog(QByteArray)));

        QThread *t = new QThread();
        server->initialize(*t);
        server->moveToThread(t);
        t->start();
    } else if (type == "client") {
        quint16 port = 61723;
        QString ip = "10.0.0.10";
        Client *client = new Client(ip, port);

        connect(this, SIGNAL(msgInput(QString)), client, SLOT(sendMsg(QString)));
        connect(client, SIGNAL(msgReceived(QByteArray)), this, SLOT(updateLog(QByteArray)));

        QThread *t = new QThread();
        client->initialize(*t);
        client->moveToThread(t);
        t->start();
    }

    ui->lineEdit->installEventFilter(this);




}

bool SecureChat::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == ui->lineEdit) {
        if (event->type() == QEvent::KeyPress) {
            QKeyEvent *keyEvent = static_cast<QKeyEvent*>(event);
            if (keyEvent->key() == Qt::Key_Return) {
                // TODO call function that updates thread with text to send
                emit msgInput(ui->lineEdit->text());
                ui->textBrowser->append("You: " + ui->lineEdit->text());
                ui->lineEdit->clear();
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

