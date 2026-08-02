#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableWidget>
#include <QTextEdit>
#include <QComboBox>
#include <QPushButton>
#include "snifferthread.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartClicked();
    void onStopClicked();
    void onSaveClicked();
    void onPacketCaptured(int index);
    void onPacketSelected(int row, int column);
    void onErrorOccurred(QString msg);

private:
    void setupUi();
    QString getMacString(const uint8_t mac[6]);
    QString getIpString(const uint8_t ip[4]);

    QComboBox *comboInterface;
    QPushButton *btnStart;
    QPushButton *btnStop;
    QPushButton *btnSave;
    QTableWidget *tablePackets;
    QTextEdit *textDetails;
    
    SnifferThread *sniffer;
};

#endif // MAINWINDOW_H