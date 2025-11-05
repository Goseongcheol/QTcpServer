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

    void writeLog(quint8 cmd, QString data, QString clientIp, quint16 clientPort);
    QString logFilePath;
    void addUserRow(QTcpSocket* client, const clientInfo& info);
    void initUserTable();
    bool isUserIdDuplicate(const QString &userId) const ;
    void removeUserRow(QTcpSocket* client);
    void broadcastMessage(quint8 CMD, QString dataStr, QTcpSocket* excludeClient);
    void ackOrNack(QTcpSocket* client, quint8 cmd, quint8 refCMD, quint8 code);
    void userListSend(quint8 CMD, QTcpSocket* client);
    void broadcastMessage(quint8 CMD, QByteArray data);


signals:
    void clientConnected(QTcpSocket* client, const QString& peer);
    void clientDisconnected(QTcpSocket* client, const QString& peer, const QString& reason);
    void messageReceived(QTcpSocket* client, const QByteArray& line);


private slots:
    void newConnection();
    void readyRead();
    void disconnected();
    void on_SendButton_clicked();
    void on_disConnectButton_clicked();
};
#endif // MAINWINDOW_H
