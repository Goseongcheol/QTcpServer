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
        writeLog(0,"server on",ip, port);
    } else {
        writeLog(0,"server fail",ip, port);
    }
}

MainWindow::~MainWindow()
{
    delete ui;
    server->close();
}

void MainWindow::newConnection()
{
    QTcpSocket *client = server->nextPendingConnection();
    // 클라이언트 연결
    connect(client, &QTcpSocket::readyRead, this, &MainWindow::readyRead);
    connect(client, &QTcpSocket::disconnected, this, &MainWindow::disconnected);
}

// 프로토콜 처리
void MainWindow::readyRead()
{
    QTcpSocket *client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;

    QByteArray packet = client->readAll();

    quint8 STX  = quint8(packet[0]);
    quint8 CMD  = quint8(packet[1]);
    quint8 lenH = quint8(packet[2]);
    quint8 lenL = quint8(packet[3]);
    quint16 LEN = (quint16(lenH) << 8) | lenL;

    // 패킷 형식(사이즈로) 검증
    if (packet.size() < 1 + 1 + 2 + LEN + 1 + 1) {
        qDebug() << "packet size error";
        //
        // nack 보내기
        //
        return;
    }

    QByteArray data = packet.mid(4, LEN);
    quint8 checksum = quint8(packet[4 + LEN]);
    quint8 ETX      = quint8(packet[5 + LEN]);

    // 체크섬 계산 (클라이언트와 동일)
    quint32 sum = CMD + lenH + lenL;
    for (unsigned char c : data)
        sum += c;
    quint8 calChecksum = quint8(sum % 256);

    // STX, ETX 검증
    if(STX != 2 || ETX != 3){
        //nack stx,erx 오류 6번으로
        ackOrNack(client,0x09,0x01,0x06);
        return;
    }

    // 받은 checksum과 계산한 checksum 확인하기
    if(checksum != calChecksum)
    {
        //nack - checksum 오류
        ackOrNack(client,0x09,0x01,0x01);
        return;
    }
    // CMD 에 맞게 따로 처리
    switch (CMD){
    // CONNECT (0x01)
    case 1 :{
        // C++ 에서는 switch case 안에 변수 선언을 하면 다음 case로 넘어갈떄 변수초기화 오류가 발생할수있어서  case문을 {} 묶지 않으면 사용 불가하게 만듬
        QString ID = data.mid(0,4).trimmed();
        QString NAME = data.mid(4,16).trimmed();

        QString loginLogData = QString("%1|%2 USER LOGIN!").arg(ID,NAME);

        clientInfo info;
        info.userId = ID;
        info.userName = NAME;
        info.clientIp = client->peerAddress().toString();
        info.clientPort = client->peerPort();

        client_list.insert(client, info);

        if (m_userIdToSocket.contains(ID)) {
            // log 추가
            client->disconnectFromHost();
            return;
        }

        m_userIdToSocket.insert(ID, client);

        addUserRow(client, info);

        //USER_JOIN 보내기
        QByteArray idBytes = ID.toUtf8();
        if (idBytes.size() > 4) idBytes.truncate(4);
        else idBytes.append(QByteArray(4 - idBytes.size(), ' '));

        QByteArray nameBytes = NAME.toUtf8();
        if (nameBytes.size() > 16) nameBytes.truncate(16);
        else nameBytes.append(QByteArray(16 - nameBytes.size(), ' '));

        QByteArray ipBytes = client->peerAddress().toString().toUtf8();
        if (ipBytes.size() > 15) ipBytes.truncate(15);
        else ipBytes.append(QByteArray(15 - ipBytes.size(), ' '));

        quint16 port = client->peerPort();
        QByteArray portBytes;
        portBytes.append(static_cast<char>((port >> 8) & 0xFF));
        portBytes.append(static_cast<char>(port & 0xFF));


        QByteArray userJoinData = idBytes + nameBytes+ ipBytes + portBytes ;

        //CONNECT ACK 보내기 부분
        ackOrNack(client,0x08,0x01,0x00);


        //USER_JOIN 작성중
        broadcastMessage(0x03, userJoinData, client);

        //
        //USER_LIST 보내기 작성
        //

        writeLog(CMD,loginLogData,client->peerAddress().toString(), client->peerPort());

        //
        //user_join
        //user_list
        // 추가 후
        // ack or nack 전송
        //


        break;
    }
    case 8 :
    {
        //ack
        qDebug() << "ack";

        break;
    }
    case 9 :
    {
        //Nack
        qDebug() << "nack";

        break;
    }
    case 18 :
    {
        //chat으로 메세지 송수신 + 브로드캐스트
        qDebug() << "real DATA:" << data;
        qDebug() << "chat ";

        QString ID = data.mid(0,4);
        QString MSG = data.mid(4);

        //ID와 MSG 로 받은 메세지 구분해서 처리하기

        QString chatLogData = QString("%1:%2").arg(ID,MSG);

        writeLog(CMD,chatLogData,client->peerAddress().toString(), client->peerPort());

        //??
        auto it = client_list.find(client);
        const clientInfo& info = it.value();

        qDebug() << "client IP : " << info.clientIp ;
        //
        // 받은 메세지 처리하기 추가 전체 클라이언트에게 브로드캐스트
        //

        break;
    }
    default :
    {
        qDebug() << "none";
        break;
    }
    }
}

// qmap과 qhash에 매핑된 소켓 제거 + userleave 메세지 브로드캐스트 + 로그 출력
void MainWindow::disconnected()
{
    QTcpSocket *client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;


    auto it = client_list.find(client);
    if (it != client_list.end()) {
        const QString userId = it.value().userId;
        const QString userName = it.value().userName;
        quint8 CMD = 4;
        QString userLeaveLog = QString ("%1|%2 USER LOGOUT!").arg(userId,userName);

        broadcastMessage(CMD, userId, client);
        writeLog(CMD,userLeaveLog,client->peerAddress().toString(), client->peerPort());

        m_userIdToSocket.remove(userId);

        removeUserRow(client);

        client_list.erase(it);
    }

    client->deleteLater();
}
void MainWindow::writeLog(quint8 cmd, QString data, QString clientIp, quint16 clientPort)
{
    QString logCmd = "";
    if( cmd == 1){
        logCmd = "[CONNECT]";
    }else if(cmd == 2){
        logCmd = "[LIST]";
    }else if(cmd == 3){
        logCmd = "[JOIN]";
    }else if(cmd == 4){
        logCmd = "[LEAVE]";
    }else if(cmd == 8){
        logCmd = "[ack]";
    }else if(cmd == 9){
        logCmd = "[nack]";
    }else if(cmd == 18){
        logCmd = "[CHAT_MSG]";
    }else if(cmd == 19){
        logCmd = "[DISCONNECT]";
    }else {
        logCmd = "[NONE]";
    }

    QDateTime currentDateTime = QDateTime::currentDateTime();
    QString logTime = currentDateTime.toString("[yyyy-MM-dd HH:mm:ss]"); //폴더에 날짜가 표시 되지만 프로그램을 며칠동안 종료하지 않을 경우에 날짜를 명확하게 확인하려고 yyyy-MM-dd 표시
    QString uiLogData = QString("%1\n[%2:%3]\n%4 %5")
                            .arg(logTime,
                                 clientIp)
                            .arg(clientPort) // port가 quint16 으로 작성했었음 오류 나옴
                            .arg(logCmd,
                                 data);

    QString logData = QString("%1[%2:%3]%4 %5")
                          .arg(logTime,
                               clientIp)
                          .arg(clientPort)
                          .arg(logCmd,
                               data);

    ui->logText->append(uiLogData);

    //로그파일 열고 적기
    QFileInfo fileInfo(logFilePath);
    QDir dir;
    dir.mkpath(fileInfo.path());

    QFile File(logFilePath);

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

//유저테이블 초기화
void MainWindow::initUserTable()
{
    auto *tw = ui->userListTableWidget;
    tw->setColumnCount(4); // UserID, UserName, UserIP, UserPort

    tw->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    tw->setSelectionBehavior(QAbstractItemView::SelectRows);
    tw->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void MainWindow::addUserRow(QTcpSocket* client, const clientInfo& info)
{
    auto *tw = ui->userListTableWidget;

    const int row = tw->rowCount();
    tw->insertRow(row);

    tw->setItem(row, 0, new QTableWidgetItem(info.userId));
    tw->setItem(row, 1, new QTableWidgetItem(info.userName));
    tw->setItem(row, 2, new QTableWidgetItem(info.clientIp));
    tw->setItem(row, 3, new QTableWidgetItem(QString::number(info.clientPort)));

    for (int c = 0; c < 4; ++c) {
        auto *it = tw->item(row, c);
        it->setTextAlignment(Qt::AlignCenter);
    }

    // 소켓→행 매핑 저장 행에서 소켓 정보를 찾아 매칭하기위해서 ( 선택 유저 메세지 전송 하기위해 아직 미구현 )
    m_rowOfSocket.insert(client, row);
}


//유저 지우기
void MainWindow::removeUserRow(QTcpSocket* client)
{
    auto it = m_rowOfSocket.find(client);
    if (it == m_rowOfSocket.end()) return;

    int row = it.value();
    ui->userListTableWidget->removeRow(row);
    m_rowOfSocket.erase(it);

    // 인덱스 조정 (선택사항)
    for (auto j = m_rowOfSocket.begin(); j != m_rowOfSocket.end(); ++j)
        if (j.value() > row) j.value() -= 1;
}

// 전체 소켓 브로드 캐스트 메세지 보내기
void MainWindow::broadcastMessage(quint8 CMD, QString dataStr, QTcpSocket* excludeClient)
{
    QByteArray data = dataStr.toUtf8();
    QByteArray packet;
    quint8 STX = 0x02;
    quint16 len = data.size();
    quint8 ETX = 0x03;

    packet.append(STX);
    packet.append(CMD);
    packet.append((len >> 8) & 0xFF);
    packet.append(len & 0xFF);
    packet.append(data);

    quint32 sum = CMD + ((len >> 8) & 0xFF) + (len & 0xFF);
    for (unsigned char c : data)
        sum += c;
    quint8 checksum = sum % 256;

    packet.append(checksum);
    packet.append(ETX);

    for (auto it = client_list.constBegin(); it != client_list.constEnd(); ++it)
    {
        QTcpSocket* client = it.key();

        if (client == excludeClient)
            continue;

        if (client->state() == QAbstractSocket::ConnectedState)
            client->write(packet);
    }
}



void MainWindow::ackOrNack(QTcpSocket* client, quint8 cmd, quint8 refCMD, quint8 code)
{
    QByteArray data;
    data.append(refCMD);
    data.append(code);

    quint16 len = data.size();

    quint8 STX = 0x02;
    quint8 ETX = 0x03;

    QByteArray packet;
    packet.append(STX);
    packet.append(cmd);
    packet.append((char)((len >> 8) & 0xFF));
    packet.append((char)(len & 0xFF));
    packet.append(data);

    quint32 sum = cmd + ((len >> 8) & 0xFF) + (len & 0xFF);
    for (unsigned char c : data)
        sum += c;

    quint8 checksum = sum % 256;
    packet.append(checksum);
    packet.append(ETX); // ETX

    client->write(packet);
    client->flush();
}




