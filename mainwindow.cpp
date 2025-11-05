#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QHostAddress>
#include <QDataStream>
#include <QDateTime>
#include <QFileInfo>
#include <QDir>
#include <QTcpSocket>
#include <QShortcut>

MainWindow::MainWindow(const QString& ip, quint16 port, const QString& filePath, QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    serverIp = ip;
    serverPort = port;

    logFilePath = filePath;

    server = new QTcpServer(this);

    connect(server, &QTcpServer::newConnection, this, &MainWindow::newConnection);

    if (server->listen(QHostAddress(ip), port)) {
        writeLog(0,"server on",ip, port);
    } else {
        writeLog(0,"server fail",ip, port);
    }


    new QShortcut(QKeySequence(Qt::Key_Enter), this, [this]{
        on_SendButton_clicked();
    });

}

MainWindow::~MainWindow()
{
    delete ui;
    server->close();
}

void MainWindow::newConnection()
{
    QTcpSocket *client = server->nextPendingConnection();
    connect(client, &QTcpSocket::readyRead, this, &MainWindow::readyRead);
    connect(client, &QTcpSocket::disconnected, this, &MainWindow::disconnected);
}

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

    if (packet.size() < 1 + 1 + 2 + LEN + 1 + 1) {
        ackOrNack(client,0x09,0x01,0x07);
        return;
    }

    QByteArray data = packet.mid(4, LEN);
    quint8 checksum = quint8(packet[4 + LEN]);
    quint8 ETX      = quint8(packet[5 + LEN]);

    quint32 sum = CMD + lenH + lenL;
    for (unsigned char c : data)
        sum += c;
    quint8 calChecksum = quint8(sum % 256);

    if(STX != 2 || ETX != 3){
        ackOrNack(client,0x09,0x01,0x06);
        return;
    }

    if(checksum != calChecksum)
    {
        ackOrNack(client,0x09,0x01,0x01);
        return;
    }

    // CMD 에 맞게 따로 처리
    switch (CMD){
    // CONNECT (0x01)
    case 1 :{
        qDebug() << "connect client info";
        qDebug() << client;
        qDebug() << data;


        QString ID = data.mid(0,4).trimmed();
        QString NAME = data.mid(4,16).trimmed();

        QString loginLogData = QString("%1|%2 USER LOGIN!").arg(ID,NAME);

        clientInfo info;
        info.userId = ID;
        info.userName = NAME;
        info.clientIp = client->peerAddress().toString();
        info.clientPort = client->peerPort();

        if (m_userIdToSocket.contains(ID)) {
            ackOrNack(client,0x09,0x01,0x05);
            client->disconnectFromHost();
            return;
        }

        client_list.insert(client, info);
        m_userIdToSocket.insert(ID, client);
        addUserRow(client, info);

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

        ackOrNack(client,0x08,0x01,0x00);

        client->waitForBytesWritten(200);

        broadcastMessage(0x03, userJoinData, client);

        client->waitForBytesWritten(200);

        writeLog(CMD,loginLogData,client->peerAddress().toString(), client->peerPort());

        client->waitForBytesWritten(200);

        userListSend(0x02,client);

        break;
    }
    case 8 :
    // ACK[0X08]
    {
        quint8 ackCMD = quint8(packet[4]);
        QString ackMessage = "해당 CMD 성공";
        writeLog(ackCMD, ackMessage,client->peerAddress().toString(),client->peerPort());
        break;
    }
    case 9 :
    // NACK[0X09]
    {
        quint8 nackCMD = quint8(packet[4]);
        quint8 nackErrorCode = quint8(packet[5]);
        if(nackErrorCode == 1)
        {
            QString nackMessage = "checksum error";
         writeLog(nackCMD, nackMessage,client->peerAddress().toString(),client->peerPort());
        }else if(nackErrorCode == 2)
        {
            QString nackMessage = "Unknown CMD";
         writeLog(nackCMD, nackMessage,client->peerAddress().toString(),client->peerPort());
        }else if(nackErrorCode == 3)
        {
            QString nackMessage = "Invalid Data";
         writeLog(nackCMD, nackMessage,client->peerAddress().toString(),client->peerPort());
        }else if(nackErrorCode == 4)
        {
            QString nackMessage = "Time Out";
         writeLog(nackCMD, nackMessage,client->peerAddress().toString(),client->peerPort());
        }else if(nackErrorCode == 5)
        {
            QString nackMessage = "Permossion Denied";
         writeLog(nackCMD, nackMessage,client->peerAddress().toString(),client->peerPort());
        }else{
            QString nackMessage = "undefind code";
        writeLog(nackCMD, nackMessage,client->peerAddress().toString(),client->peerPort());
        }
        break;

    }
    case 18 :
    // CHAT[0X12]
    {

        QString ID = data.mid(0,16).trimmed();
        QString MSG = data.mid(16);
        QString chatLogData = QString("%1:%2").arg(ID,MSG);
        writeLog(CMD,chatLogData,client->peerAddress().toString(), client->peerPort());
        broadcastMessage(0x12, data, client);\
        break;
    }
    default :
    {
        break;
    }
    }
}

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
    QString logTime = currentDateTime.toString("[yyyy-MM-dd HH:mm:ss]");
    QString uiLogData = QString("%1\n[%2:%3]\n%4 %5")
                            .arg(logTime,
                                 clientIp)
                            .arg(clientPort)
                            .arg(logCmd,
                                 data);

    QString logData = QString("%1[%2:%3]%4 %5")
                          .arg(logTime,
                               clientIp)
                          .arg(clientPort)
                          .arg(logCmd,
                               data);

    ui->logText->append(uiLogData);

    QFileInfo fileInfo(logFilePath);
    QDir dir;
    dir.mkpath(fileInfo.path());

    QFile File(logFilePath);

    if (File.open(QFile::WriteOnly | QFile::Append | QFile::Text))
    {
        QTextStream SaveFile(&File);
        SaveFile << logData << "\n";
        File.close();
    }
    else
    {
        qDebug() << "logfile error" ;
    }
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

    m_rowOfSocket.insert(client, row);
}

void MainWindow::removeUserRow(QTcpSocket* client)
{
    auto it = m_rowOfSocket.find(client);
    if (it == m_rowOfSocket.end()) return;

    int row = it.value();
    ui->userListTableWidget->removeRow(row);
    m_rowOfSocket.erase(it);

    for (auto j = m_rowOfSocket.begin(); j != m_rowOfSocket.end(); ++j)
        if (j.value() > row) j.value() -= 1;
}

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

    for (auto list = client_list.constBegin(); list != client_list.constEnd(); ++list)
    {
        QTcpSocket* client = list.key();
        if (client == excludeClient)
            continue;
        if (client->state() == QAbstractSocket::ConnectedState)
        {
            client->write(packet);
            client->waitForBytesWritten(2000);
        }
    }
}

void MainWindow::broadcastMessage(quint8 CMD, QByteArray data)
{
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

    for (auto list = client_list.constBegin(); list != client_list.constEnd(); ++list)
    {
        QTcpSocket* client = list.key();

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
    packet.append(ETX);

    client->write(packet);
}

void MainWindow::userListSend(quint8 CMD, QTcpSocket* client)
{
    QByteArray packet;
    quint8 STX = 0x02;
    quint8 ETX = 0x03;

    QByteArray data;

    quint8 count = client_list.size();

    data.append(count);

    for (auto it = client_list.begin(); it != client_list.end(); ++it)
    {
        const clientInfo &info = it.value();

        QByteArray idBytes   = info.userId.toUtf8();
        QByteArray nameBytes = info.userName.toUtf8();
        QByteArray ipBytes   = info.clientIp.toUtf8();

        QByteArray portBytes;
        portBytes.append(static_cast<char>((info.clientPort >> 8) & 0xFF));
        portBytes.append(static_cast<char>(info.clientPort & 0xFF));

        if (idBytes.size()   < 4)  idBytes.append(QByteArray(4 - idBytes.size(), ' '));
        if (nameBytes.size() < 16) nameBytes.append(QByteArray(16 - nameBytes.size(), ' '));
        if (ipBytes.size()   < 15) ipBytes.append(QByteArray(15 - ipBytes.size(), ' '));

        data.append(idBytes);
        data.append(nameBytes);
        data.append(ipBytes);
        data.append(portBytes);
    }

    quint16 len = data.size();

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

    client->write(packet);
    client->waitForBytesWritten(200);

}




void MainWindow::on_SendButton_clicked()
{
    QString serverName = "Server" ;
    QByteArray nameBytes = serverName.toUtf8();
    if (nameBytes.size() > 16)
    {
        nameBytes.truncate(16);
    }
    else
    {
        nameBytes.append(QByteArray(16 - nameBytes.size(), ' '));
    }

    QString chatData = ui->sendText->toPlainText();

    QByteArray chatBytes = chatData.toUtf8();

    QByteArray data = nameBytes + chatBytes ;


    QString logData = QString("%1 : %2").arg(serverName,
                                             ui->sendText->toPlainText());
    qint8 cmd = 0x12;

    broadcastMessage(cmd,data);

    writeLog(cmd,logData,serverIp,serverPort);

    ui-> sendText -> clear();
}


void MainWindow::on_disConnectButton_clicked()
{

        int row = ui->userListTableWidget->currentRow();
        if (row < 0)
            return;

        QTableWidgetItem *idItem = ui->userListTableWidget->item(row, 0);
        if (!idItem)
            return;

        QString userId = idItem->text().trimmed();

        QTcpSocket *sock = m_userIdToSocket.value(userId, nullptr);
        if (!sock) {
            return;
        }

        sock->disconnectFromHost();
}

