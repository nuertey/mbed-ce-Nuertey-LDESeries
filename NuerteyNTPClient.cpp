#include "NuerteyNTPClient.h"
#include "Utilities.h"
#include "lwip/arch.h"
#include "lwip/tcp.h"
#include "lwip/netif.h"

// Virtual cluster of timeservers providing reliable easy to use NTP 
// service for millions of clients.
const std::string NuerteyNTPClient::DEFAULT_NTP_SERVER_ADDRESS("2.pool.ntp.org");

const uint16_t    NuerteyNTPClient::DEFAULT_NTP_SERVER_PORT;
const uint16_t    NuerteyNTPClient::DEFAULT_NTP_CLIENT_PORT;
const uint32_t    NuerteyNTPClient::NTP_VERSUS_UNIX_TIMESTAMP_DELTA;

NuerteyNTPClient::NuerteyNTPClient(NetworkInterface * pNetworkInterface,
                      const std::string & server, const uint16_t & port)
    : m_pNetworkInterface(pNetworkInterface)
    , m_NTPServerAddress(server)
    , m_NTPServerPort(port)
{
}

void NuerteyNTPClient::SynchronizeRTCTimestamp(const uint32_t & timeout)
{
    Utilities::g_STDIOMutex.lock();
    printf("\r\n\r\nDefault date and time before NTP is :-> [%s UTC]\r\n", Utilities::WhatTimeNow().c_str());
    Utilities::g_STDIOMutex.unlock();

    struct NTPPacket pkt;

    pkt.li = 3; // Leap Indicator : "clock not synchronized"; Only significant in server messages.
    pkt.vn = 4; // Version Number : "NTP/SNTP version 4"
    pkt.mode = 3; // Mode : "Client"
    pkt.stratum = 0; // Stratum. Significant only in SNTP server messages.
    pkt.poll = 0; // Poll Interval. Significant only in SNTP server messages.
    pkt.precision = 0; // Precision. Significant only in server messages.
    pkt.rootDelay = 0; // Root Delay. Significant only in server messages.
    pkt.rootDispersion = 0; // Root Dispersion. Significant only in server messages.
    pkt.refId = 0; // Reference Identifier. Significant only in server messages.
    pkt.refTm_s = 0; // Reference Timestamp. Significant only in server messages.
    pkt.origTm_s = 0; // Originate Timestamp. Significant only in server messages.
    pkt.rxTm_s = 0; // Receive Timestamp. Significant only in server messages.
    pkt.txTm_s = htonl(NTP_VERSUS_UNIX_TIMESTAMP_DELTA + time(NULL)); // WARN: We are in LE format, network byte order is BE
    pkt.refTm_f = pkt.origTm_f = pkt.rxTm_f = pkt.txTm_f = 0;

    SocketAddress serverSocketAddress;
    SocketAddress clientSocketAddress;

    nsapi_size_or_error_t retVal;
    do
    {
        printf("\r\nPerforming DNS lookup for : \"%s\" ...", m_NTPServerAddress.c_str());
        retVal = m_pNetworkInterface->gethostbyname(m_NTPServerAddress.c_str(), &serverSocketAddress);
        if (retVal < 0)
        {
            printf("\r\nError! On DNS lookup, Network returned: [%d] -> %s", retVal, ToString(retVal).c_str());
        }
    }
    while (retVal < 0);

    serverSocketAddress.set_port(m_NTPServerPort);

    UDPSocket sock;
    sock.bind(DEFAULT_NTP_CLIENT_PORT);
    sock.set_blocking(false);
    sock.set_timeout(timeout); // Set timeout as we are on embedded.

    sock.open(m_pNetworkInterface);

    printf("\r\nPinging NTP Time Server at : \"%s\" ...", serverSocketAddress.get_ip_address());
    sock.sendto(serverSocketAddress, static_cast<void *>(&pkt), sizeof(NTPPacket));

    do
    {
        printf("\r\nWaiting for NTP Time Server response ...");
        nsapi_size_or_error_t status = sock.recvfrom(&clientSocketAddress, static_cast<void *>(&pkt), sizeof(NTPPacket));
        printf("\r\nReceived a response from : \"%s\" .", clientSocketAddress.get_ip_address());

        if (status < (nsapi_size_or_error_t)sizeof(NTPPacket))
        {
            if (status < 0)
            {
                printf("\r\nError! Socket recvfrom returned: [%d] -> %s", status, ToString(status).c_str());
            }
            else
            {
                printf("\r\nError! Partial data returned on socket read: [%d]", status);
            }
        }

        // TBD, Nuertey Odzeyem : we would need a DNS Resolver to be able to compare the incoming address with the DNS name.
    }
    while (strcmp(serverSocketAddress.get_ip_address(), clientSocketAddress.get_ip_address()) != 0);

    if (pkt.stratum == 0)  // "kiss-o'-death message"
    {
        printf("\r\nReceived a kiss-o'-death message.");
    }
    else
    {
        // Correct for Endianness ...
        pkt.refTm_s = ntohl(pkt.refTm_s);
        pkt.refTm_f = ntohl(pkt.refTm_f);
        pkt.origTm_s = ntohl(pkt.origTm_s);
        pkt.origTm_f = ntohl(pkt.origTm_f);
        pkt.rxTm_s = ntohl(pkt.rxTm_s);
        pkt.rxTm_f = ntohl(pkt.rxTm_f);
        pkt.txTm_s = ntohl(pkt.txTm_s);
        pkt.txTm_f = ntohl(pkt.txTm_f);

        // Compute offset, see RFC 4330 p.13
        uint32_t destTm_s = (NTP_VERSUS_UNIX_TIMESTAMP_DELTA + time(NULL));
        int64_t offset = ((int64_t)(pkt.rxTm_s - pkt.origTm_s) + (int64_t)(pkt.txTm_s - destTm_s)) / 2; // Avoid overflow
        printf("\r\nServer deduced that client transmitted this timestamp: [%lu]", pkt.txTm_s);
        printf("\r\nCalculated system clock offset: [%lld]", offset);

        // Seed the RTC accordingly...
        set_time(time(NULL) + offset);

        printf("\r\n\r\nSynchronized date and time after NTP is :-> [%s UTC]\r\n", Utilities::WhatTimeNow().c_str());
    }

    sock.close();
}
