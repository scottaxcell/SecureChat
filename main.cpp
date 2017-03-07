#include "securechat.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QStringList args = QCoreApplication::arguments();
    SecureChat w(args);
    w.show();

    return a.exec();
}
