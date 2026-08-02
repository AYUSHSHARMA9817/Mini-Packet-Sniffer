#include "mainwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QSplitter>
#include <QString>
#include <QFileDialog>  // For Save File dialog
#include <QFile>        // For writing files
#include <QTextStream>  // For writing text streams

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), sniffer(new SnifferThread(this)) {
    setupUi();
    
    comboInterface->addItems(SnifferThread::getAvailableInterfaces());

    connect(btnStart, &QPushButton::clicked, this, &MainWindow::onStartClicked);
    connect(btnStop, &QPushButton::clicked, this, &MainWindow::onStopClicked);
    connect(btnSave, &QPushButton::clicked, this, &MainWindow::onSaveClicked);
    connect(sniffer, &SnifferThread::packetCaptured, this, &MainWindow::onPacketCaptured);
    connect(sniffer, &SnifferThread::errorOccurred, this, &MainWindow::onErrorOccurred);
    connect(tablePackets, &QTableWidget::cellClicked, this, &MainWindow::onPacketSelected);
}

MainWindow::~MainWindow() {
    sniffer->stop();
    sniffer->wait();
}

void MainWindow::setupUi() {
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    resize(900, 700);
    setWindowTitle("Network Sniffer");

    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    QHBoxLayout *topLayout = new QHBoxLayout();

    comboInterface = new QComboBox();
    btnStart = new QPushButton("Start Capture");
    btnStop = new QPushButton("Stop Capture");
    btnSave = new QPushButton("Save to File");
    btnStop->setEnabled(false);

    topLayout->addWidget(comboInterface);
    topLayout->addWidget(btnStart);
    topLayout->addWidget(btnStop);
    topLayout->addWidget(btnSave);
    topLayout->addStretch();

    QSplitter *splitter = new QSplitter(Qt::Vertical);
    
    tablePackets = new QTableWidget(0, 5);
    tablePackets->setHorizontalHeaderLabels({"No.", "Protocol", "Source", "Destination", "Length"});
    tablePackets->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    tablePackets->setSelectionBehavior(QAbstractItemView::SelectRows);
    tablePackets->setEditTriggers(QAbstractItemView::NoEditTriggers);

    textDetails = new QTextEdit();
    textDetails->setReadOnly(true);
    textDetails->setFontFamily("monospace");

    splitter->addWidget(tablePackets);
    splitter->addWidget(textDetails);
    
    mainLayout->addLayout(topLayout);
    mainLayout->addWidget(splitter);
}

void MainWindow::onStartClicked() {
    tablePackets->setRowCount(0);
    textDetails->clear();
    sniffer->setInterface(comboInterface->currentText());
    sniffer->start();
    
    btnStart->setEnabled(false);
    btnStop->setEnabled(true);
    comboInterface->setEnabled(false);
}

void MainWindow::onStopClicked() {
    sniffer->stop();
    btnStart->setEnabled(true);
    btnStop->setEnabled(false);
    comboInterface->setEnabled(true);
}

void MainWindow::onSaveClicked() {
    // Open a save file dialog
    QString fileName = QFileDialog::getSaveFileName(this, "Save Packets", "", "Text Files (*.txt);;All Files (*)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Cannot open file for writing.");
        return;
    }

    QTextStream out(&file);
    for (int i = 0; i < tablePackets->rowCount(); i++) {
        int index = tablePackets->item(i, 0)->text().toInt() - 1;
        Packet p = Packets[index];

        out << "Packet #" << (index + 1) << "\n";
        out << "Protocol: " << tablePackets->item(i, 1)->text() << "\n";
        out << "Source: " << tablePackets->item(i, 2)->text() << "\n";
        out << "Destination: " << tablePackets->item(i, 3)->text() << "\n";
        out << "Length: " << tablePackets->item(i, 4)->text() << " bytes\n";
        
        if (p.payload_len > 0) {
            out << "Payload (ASCII):\n";
            for (int j = 0; j < p.payload_len; j++) {
                char c = (char)p.payload[j];
                // If it is a printable ASCII character, write it. Otherwise write a dot.
                if (c >= 32 && c <= 126) out << c;
                else out << ".";
            }
            out << "\n";
        }
        out << "--------------------------------------------------\n";
    }
    
    file.close();
    QMessageBox::information(this, "Success", "Packets saved successfully to:\n" + fileName);
}

void MainWindow::onErrorOccurred(QString msg) {
    QMessageBox::critical(this, "Error", msg);
    onStopClicked();
}

QString MainWindow::getMacString(const uint8_t mac[6]) {
    return QString::asprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

QString MainWindow::getIpString(const uint8_t ip[4]) {
    return QString::asprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

void MainWindow::onPacketCaptured(int index) {
    if (index >= 1000) return;
    
    Packet p = Packets[index];
    int row = tablePackets->rowCount();
    tablePackets->insertRow(row);

    tablePackets->setItem(row, 0, new QTableWidgetItem(QString::number(index + 1)));

    QString protocol = "Ethernet";
    QString src = getMacString(p.ethernet.src);
    QString dst = getMacString(p.ethernet.dest);

    if (p.network == NetworkProtocol::IPv4) {
        src = getIpString(p.ipv4.source_add);
        dst = getIpString(p.ipv4.dest_add);
        
        if (p.transport == TransportProtocol::TCP) protocol = "TCP";
        else if (p.transport == TransportProtocol::UDP) protocol = "UDP";
        else if (p.transport == TransportProtocol::ICMP) protocol = "ICMP";
        else protocol = "IPv4";
    } else if (p.network == NetworkProtocol::ARP) {
        protocol = "ARP";
    }

    tablePackets->setItem(row, 1, new QTableWidgetItem(protocol));
    tablePackets->setItem(row, 2, new QTableWidgetItem(src));
    tablePackets->setItem(row, 3, new QTableWidgetItem(dst));
    tablePackets->setItem(row, 4, new QTableWidgetItem(QString::number(p.payload_len)));
}

void MainWindow::onPacketSelected(int row, int column) {
    Q_UNUSED(column);
    int index = tablePackets->item(row, 0)->text().toInt() - 1;
    if (index < 0 || index >= Packet_count) return;

    Packet p = Packets[index];
    QString details = QString("Packet #%1 Details:\n").arg(index + 1);
    
    if (p.payload_len > 0) {
        // --- 1. Hex Dump ---
        details += "\n[ Payload - Hex Dump ]\n";
        for (int i = 0; i < p.payload_len; i++) {
            details += QString::asprintf("%02X ", p.payload[i]);
            if ((i + 1) % 16 == 0) details += "\n";
        }

        // --- 2. ASCII / English Dump ---
        details += "\n\n[ Payload - Readable Text ]\n";
        for (int i = 0; i < p.payload_len; i++) {
            char c = (char)p.payload[i];
            // ASCII 32 to 126 are standard readable characters (letters, numbers, punctuation)
            if (c >= 32 && c <= 126) {
                details += c;
            } else {
                details += "."; // Replace raw binary with dots
            }
            
            // Optional: Break text into 64-character lines to make it easier to read
            if ((i + 1) % 64 == 0) details += "\n";
        }
    } else {
        details += "\nNo Payload Data.";
    }

    textDetails->setText(details);
}