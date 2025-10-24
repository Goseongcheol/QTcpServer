#include "mainwindow.h"

#include <QApplication>
#include <QSettings>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    // 실행 경로의 config.ini 파일 읽어오기
    QSettings settings("config.ini", QSettings::IniFormat);
    settings.beginGroup("SERVER");
    QString ip = settings.value("IP").toString();
    quint16 port = static_cast<quint16>(settings.value("PORT").toUInt());
    settings.endGroup();

    // MainWindow 에 ini파일의 ip와 port 전달
    MainWindow w(ip, port);
    w.show();
    return a.exec();
}
