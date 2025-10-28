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

    QSet<QTcpSocket*>                clients;
    QHash<QTcpSocket*, QByteArray>   buffers;

    bool startServer(const QString& ip, quint16 port);
    void stopServer();
    void writeLog(quint8 cmd, QString data, const QString& filePath, QString clientIp, QString clientPort);
    QString logFilePath;


signals:
    void started(int port);
    void stopped();
    void clientConnected(QTcpSocket* client, const QString& peer);
    void clientDisconnected(QTcpSocket* client, const QString& peer, const QString& reason);
    void messageReceived(QTcpSocket* client, const QByteArray& line);
    void errorOccurred(const QString& err);

private slots:
    void newConnection();
    void readyRead();
    void disconnected();
    // void onSocketError(QAbstractSocket::SocketError);

};
#endif // MAINWINDOW_H
