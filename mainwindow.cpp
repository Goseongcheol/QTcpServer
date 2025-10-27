#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QHostAddress>
#include <QDataStream>
#include <QDateTime>
#include <QFileInfo>
#include <QDir>
#include <QTcpSocket>

MainWindow::MainWindow(const QString& ip, quint16 port, const QString& filePath, QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    logFilePath = filePath;

    server = new QTcpServer(this);

    connect(server, &QTcpServer::newConnection, this, &MainWindow::newConnection);

    if (server->listen(QHostAddress(ip), port)) {
        qDebug() << "Server started on" << ip << ":" << port;
    } else {
        qDebug() << "Server failed:" << server->errorString();
    }
}

MainWindow::~MainWindow()
{
    delete ui;
    server->close();
}

// 새 클라이언트 접속 처리
void MainWindow::newConnection()
{
    QTcpSocket *client = server->nextPendingConnection();

    // 클라이언트 연결
    connect(client, &QTcpSocket::readyRead, this, &MainWindow::readyRead);
    connect(client, &QTcpSocket::disconnected, this, &MainWindow::disconnected);

    // 추가할 내용
    // USERID 중복 걸러내기(필수) + 모든 주고받는 통신에 checksum 확인과 ack or nack 추가하기.
    // 여기에 클라이언트 정보 받아서 사용자 목록에 추가 + 접속중인 사용자에게 목록 전송 (브로드캐스트)
    //

    qDebug() << "Client connected ";

    clients.insert(client);
}

//채팅 메세지 처리
void MainWindow::readyRead()
{
    QTcpSocket *client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;

    QByteArray data = client->readAll();
    qDebug() << "Received: " << data;

    // 추가할 내용
    // 받은데이터 로그에 남기기(ui 표시 + 해당 날짜 폴더에 로그 기록하기
    // 채팅 메세지와 connect연결 0x01 과 0x12로 구분해서 처리하면 될듯? CMD 패킷만 뜯어서 switch case 사용?
    //

}

//클라이언트 연결이 종료되면 clients 목록에서 제거
void MainWindow::disconnected()
{
    QTcpSocket *client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;

    qDebug() << "Client disconnected" ;

    // 추가할 내용
    // 여기쯤에 사용자 목록 갱신 + 전체 접속자에게 목록 보내기
    //
    clients.remove(client);
    client->deleteLater();
}

void MainWindow::writeLog(quint8 cmd, QString data, const QString& filePath, QString clientIp, QString clientPort)
{
    QString logCmd = "";
    if( cmd == 0x01){
        logCmd = "[CONNECT]";
    }else if(cmd == 0x02){
        logCmd = "[LIST]";
    }else if(cmd == 0x03){
        logCmd = "[JOIN]";
    }else if(cmd == 0x04){
        logCmd = "[LEAVE]";
    }else if(cmd == 0x08){
        logCmd = "[ack]";
    }else if(cmd == 0x09){
        logCmd = "[nack]";
    }else if(cmd == 0x12){
        logCmd = "[CHAT_MSG]";
    }else if(cmd == 0x13){
        logCmd = "[DISCONNECT]";
    }else {
        logCmd = "[NONE]";
    }


    QDateTime currentDateTime = QDateTime::currentDateTime();
    QString logTime = currentDateTime.toString("[yyyy-MM-dd HH:mm:ss]"); //폴더에 날짜가 표시 되지만 프로그램을 며칠동안 종료하지 않을 경우에 날짜를 명확하게 확인하려고 yyyy-MM-dd 표시
    QString uiLogData = QString("%1\n[%2:%3]\n%4 %5")
                            .arg(logTime,
                                 clientIp,
                                 clientPort) // port가 quint16 으로 작성했었음 오류 나옴
                            .arg(logCmd,
                                 data);

    QString logData = QString("%1[%2:%3]%4 %5")
                          .arg(logTime,
                               clientIp,
                               clientPort)
                          .arg(logCmd,
                               data);
    // ui->logText->append(logTime + "[" + client_clientIp + ":" + client_clientPort + "]" + cmd + data );

    ui->logText->append(uiLogData);

    //로그파일 열고 적기
    QFileInfo fileInfo(filePath);
    QDir dir;
    dir.mkpath(fileInfo.path());

    QFile File(filePath);

    if (File.open(QFile::WriteOnly | QFile::Append | QFile::Text))
    {
        //log에 데이터 형식 가공해서 바꿔 넣기
        QTextStream SaveFile(&File);
        SaveFile << logData << "\n";
        File.close();
    }
    else
    {
        //error 처리
    }
}
