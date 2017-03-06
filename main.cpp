#include "securechat.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    SecureChat w(argc, argv);
    w.show();

    return a.exec();
}
