#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSet>
#include <QHash>



QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(const QString& ip, quint16 port, const QString& filePath, QWidget *parent = nullptr);
    ~MainWindow();

    void sendToAll(const QByteArray& msg);
    bool sendTo(QTcpSocket* client, const QByteArray& msg);

private:
    Ui::MainWindow *ui = nullptr;

    QTcpServer *server = nullptr;
    QString     serverIp;
    quint16     serverPort = 0;

    struct clientInfo {
        QString userId;
        QString userName;
        QString clientIp;
        quint16 clientPort;
    };

    //QMap 으로 client Info 저장
    QMap<QTcpSocket*,clientInfo>     client_list;
    //userId로 socket과 매칭
    QHash<QString, QTcpSocket*> m_userIdToSocket;
    //소캣과 행 매치
    QHash<QTcpSocket*, int> m_rowOfSocket;


    bool startServer(const QString& ip, quint16 port);
    void stopServer();
    void writeLog(quint8 cmd, QString data, QString clientIp, quint16 clientPort);
    QString logFilePath;
    void addUserRow(QTcpSocket* client, const clientInfo& info);
    void initUserTable();
    bool isUserIdDuplicate(const QString &userId) const ;
    void removeUserRow(QTcpSocket* client);
    void broadcastMessage(quint8 CMD, QString dataStr, QTcpSocket* excludeClient);
    void ackOrNack(QTcpSocket* client, quint8 cmd, quint8 refCMD, quint8 code);

signals:
    void started(int port);
    void stopped();
    void clientConnected(QTcpSocket* client, const QString& peer);
    void clientDisconnected(QTcpSocket* client, const QString& peer, const QString& reason);
    void messageReceived(QTcpSocket* client, const QByteArray& line);
    void errorOccurred(const QString& err);


private slots:
    void newConnection();
    // 프로토콜 처리
    void readyRead();
    void disconnected();
    // void onSocketError(QAbstractSocket::SocketError);

};
#endif // MAINWINDOW_H
