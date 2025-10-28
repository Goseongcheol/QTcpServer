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

    //원래는 여기서 log처리해야하지만 client 의 port와 ip데이터만 변경해서 local로 돌리려고 readyRead에서 처리 예정
    // qDebug() << "Client connected ";

    clients.insert(client);
}

//채팅 메세지 처리
void MainWindow::readyRead()
{
    QTcpSocket *client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;

    QByteArray packet = client->readAll();


    quint8 STX  = static_cast<quint8>(packet[0]);
    quint8 CMD  = static_cast<quint8>(packet[1]);
    quint8 lenH = static_cast<quint8>(packet[2]);
    quint8 lenL = static_cast<quint8>(packet[3]);
    quint16 LEN = (static_cast<quint16>(lenH) << 8) | lenL;


    //패킷 형식 검증
    if (packet.size() < 1 + 1 + 2 + LEN + 1 + 1) {
        qDebug() << "packet size error";
        //nack 보내기
        return;
    }

    QByteArray data = packet.mid(4, LEN);
    quint8 checksum = static_cast<quint8>(packet[4 + LEN]);
    quint8 ETX      = static_cast<quint8>(packet[5 + LEN]);

    // 체크섬 계산 (클라이언트와 동일)
    quint32 sum = CMD + lenH + lenL;
    for (unsigned char c : data)
        sum += c;
    quint8 expect = static_cast<quint8>(sum % 256);

    // qDebug() << "STX: "  << STX << "ETX: " << ETX << "cehcksum :" << checksum << "ETX: " << expect ;

    //STX, ETX 검증
    if(STX != 2 || ETX != 3){
        qDebug() << "STX OR ETX error";
        //
        //nack보내기
        //
        return;
    }

    //받은 checksum과 계산한 checksum 확인하기
    if(checksum != expect)
    {
        qDebug() << "checksum error";
        //
        //nack보내기
        //
        return;
    }


    //CMD 에 맞게 따로 처리
    switch (CMD){
    case 1 :
         qDebug() << "DATA:" << QString::fromUtf8(data);
        //user_connect
        qDebug() << "connect";


        break;
    case 2 :
        //user_list
        qDebug() << "user_list";


        break;
    case 3 :
        //user_join
        qDebug() << "user_join";


        break;
    case 4 :
        //user_leave
        qDebug() << "user_leave";


        break;
    case 8 :
        //ack
        qDebug() << "ack";


        break;
    case 9 :
        //Nack
        qDebug() << "nack";


        break;
    case 18 :
        //chat으로 메세지 송수신 + 브로드캐스트
        qDebug() << "chat ";


        break;
    default :
        qDebug() << "DATA:" << QString::fromUtf8(data);
        qDebug() << "none";

        break;
    }

    qDebug() << "readyRead end";
}

// 추가할 내용
// 받은데이터 로그에 남기기(ui 표시 + 해당 날짜 폴더에 로그 기록하기
// 채팅 메세지와 connect연결 0x01 과 0x12로 구분해서 처리하면 될듯? CMD 패킷만 뜯어서 switch case 사용?
//





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
