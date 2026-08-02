#ifndef SNIFFERTHREAD_H
#define SNIFFERTHREAD_H

#include <QThread>
#include <QStringList>
#include <atomic>
#include "network_types.h"

class SnifferThread : public QThread
{
    Q_OBJECT
public:
    explicit SnifferThread(QObject *parent = nullptr);
    ~SnifferThread();

    static QStringList getAvailableInterfaces();
    void setInterface(const QString& iface);
    void stop();

signals:
    void packetCaptured(int index);
    void errorOccurred(QString message);

protected:
    void run() override;

private:
    void parse_eth_frame(unsigned char* buff);
    void parse_IPv4_head(unsigned char* buff);
    void parse_arp_head(unsigned char * buff);
    void parse_tcp(unsigned char* buff, uint16_t szip, uint16_t total_len);
    void parse_udp(unsigned char* buff, uint16_t szip, uint16_t total_len);
    void parse_icmp(unsigned char* buff, uint16_t szip, uint16_t total_len);
    void store_data(unsigned char* buff, uint16_t szip, uint16_t sz, uint16_t total_len);

    QString m_interface;
    std::atomic<bool> m_running;
};

#endif // SNIFFERTHREAD_H