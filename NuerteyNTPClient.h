/***********************************************************************
* @file
*
* My version of an NTP Client that synchronizes ARM Mbed-enabled target 
* RTCs to a remote time server over UDP. Consult RFC 4330 for reference.
*       
* @note      
* 
* @warning  
* 
*  Created: October 19, 2018
*   Author: Nuertey Odzeyem        
************************************************************************/
#pragma once

#include <string>
#include <cstdint>
#include "NetworkInterface.h"

class NuerteyNTPClient 
{
    static const std::string DEFAULT_NTP_SERVER_ADDRESS;
    static const uint16_t    DEFAULT_NTP_SERVER_PORT          =  123;
    static const uint16_t    DEFAULT_NTP_CLIENT_PORT          =  0; // Signifying a random port.
    
    // Difference between a UNIX timestamp (Starting Jan, 1st 1970) and a NTP timestamp (Starting Jan, 1st 1900)
    static const uint32_t    NTP_VERSUS_UNIX_TIMESTAMP_DELTA  =  2208988800ull;

    struct NTPPacket // See RFC 4330 for Simple NTP
    {
	// WARNING: We are in Little-Endian! Network is Big-Endian!
	// LSB first ...
	unsigned mode : 3;
	unsigned vn : 3;
	unsigned li : 2;

	uint8_t stratum;
	uint8_t poll;
	uint8_t precision;
	//32 bits header

	uint32_t rootDelay;
	uint32_t rootDispersion;
	uint32_t refId;

	uint32_t refTm_s;
	uint32_t refTm_f;
	uint32_t origTm_s;
	uint32_t origTm_f;
	uint32_t rxTm_s;
	uint32_t rxTm_f;
	uint32_t txTm_s;
	uint32_t txTm_f;
    } __attribute__ ((packed));
  
public:
    NuerteyNTPClient(NetworkInterface * pNetworkInterface, const std::string & server = DEFAULT_NTP_SERVER_ADDRESS, 
	      const uint16_t & port = DEFAULT_NTP_SERVER_PORT);
    
    void SynchronizeRTCTimestamp(const uint32_t & timeout = 15000);

private:
    NetworkInterface *    m_pNetworkInterface;
    std::string           m_NTPServerAddress;
    uint16_t              m_NTPServerPort;
};
