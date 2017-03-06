#include "securechat.h"
#include "ui_securechat.h"

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
        Server *server = new Server(port, this);

    } else if (type == "client") {
        quint16 port = 61723;
        QString ip = "10.0.0.10";
        Client *client = new Client(ip, port, this);
        client->connectToServer();
    }






}
