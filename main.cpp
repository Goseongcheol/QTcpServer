#include "mainwindow.h"

#include <QApplication>
#include <QSettings>
#include <QTextStream>
#include <QFile>
#include <QDateTime>
#include <QFileInfo>
#include <QDir>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QDateTime currentDateTime = QDateTime::currentDateTime();

    QString yyyymmdd = currentDateTime.toString("yyyyMMdd");
    QString HH = currentDateTime.toString("HH");
    QString HHmmss = currentDateTime.toString("HHmmss");

    QString filePath = QString("/log/%1/%2/%3.txt").arg(yyyymmdd,HH,HHmmss);
    QString nowTime = QString("%1").arg(currentDateTime.toString("yyyy-MM-dd HH:mm:ss"));
    QString ApplicationPath = QApplication::applicationDirPath();
    QString fullPath = ApplicationPath + filePath;

    QFileInfo fileInfo(fullPath);
    QDir dir;
    dir.mkpath(fileInfo.path());

    QFile File(fullPath);

    if (File.open(QFile::WriteOnly | QFile::Append | QFile::Text))
    {
        QTextStream SaveFile(&File);
        SaveFile << nowTime << " application start" << "\n";
        File.close();
    }
    else
    {
        //error 처리
    }


    // 실행 경로의 config.ini 파일 읽어오기
    QSettings settings("config.ini", QSettings::IniFormat);
    settings.beginGroup("SERVER");
    QString ip = settings.value("IP").toString();
    quint16 port = static_cast<quint16>(settings.value("PORT").toUInt());
    settings.endGroup();

    MainWindow w(ip, port, fullPath);
    w.show();
    return a.exec();
}
