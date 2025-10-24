#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QHostAddress>
#include <QTcpSocket>

MainWindow::MainWindow(const QString& ip, quint16 port, QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
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
    // 여기에 클라이언트 정보 받아서 사용자 목록에 추가 + 접속중인 사용자에게 목록 전송 (브로드캐스트)
    //

    qDebug() << "Client connected from"
             << client->peerAddress().toString() << ":" << client->peerPort();

    clients.insert(client);
}


//채팅 메세지 처리
void MainWindow::readyRead()
{
    QTcpSocket *client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;

    QByteArray data = client->readAll();
    qDebug() << "Received from" << client->peerPort() << ":" << data;

    // 추가할 내용
    // 받은데이터 로그에 남기기(ui 표시 + 해당 날짜 폴더에 로그 기록하기
    // 채팅 메세지와 connect연결 0x01 과 0x12로 구분해서 처리하면 될듯? 첫 패킷만 뜯어서 switch case 사용?
    //






}

//클라이언트 연결이 종료되면 clients 목록에서 제거
void MainWindow::disconnected()
{
    QTcpSocket *client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;

    qDebug() << "Client disconnected:" << client->peerAddress().toString()
             << ":" << client->peerPort();


    // 추가할 내용
    // 여기쯤에 사용자 목록 갱신 + 전체 접속자에게 목록 보내기
    //


    clients.remove(client);
    client->deleteLater();
}
