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

    qDebug() << "Client connected from"
             << client->peerAddress().toString() << ":" << client->peerPort();

    clients.insert(client);
}


void MainWindow::readyRead()
{
    QTcpSocket *client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;

    QByteArray data = client->readAll();
    qDebug() << "Received from" << client->peerPort() << ":" << data;

    // for (QTcpSocket *c : std::as_const(clients)) {
    //     if (c->state() == QAbstractSocket::ConnectedState)
    //         c->write(data);
    // }
}

//클라이언트 연결이 종료되면 clients 목록에서 제거
void MainWindow::disconnected()
{
    QTcpSocket *client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;

    qDebug() << "Client disconnected:" << client->peerAddress().toString()
             << ":" << client->peerPort();

    clients.remove(client);
    client->deleteLater();
}
