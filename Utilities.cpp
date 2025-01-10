#include "Utilities.h"

namespace Utilities
{
    // System identification and composed statistics variables.
    std::string                      g_NetworkInterfaceInfo;
    std::string                      g_SystemProfile;
    std::string                      g_BaseRegisterValues;
    std::string                      g_HeapStatistics;

    // By default enough buffer space for 32 Callbacks, i.e. 32*EVENTS_EVENT_SIZE
    // Reduce this amount if the target device has severely limited RAM.
    EventQueue                       gs_MasterEventQueue;
    int                              gs_NetworkDisconnectEventIdentifier(0);
    int                              gs_SensorEventIdentifier(0);
    int                              gs_HTTPEventIdentifier(0);
    int                              gs_WebSocketEventIdentifier(0);
    int                              gs_WebSocketStreamEventIdentifier(0);
    int                              gs_PrimeEventIdentifier(0);
    int                              gs_CloudCommunicationsEventIdentifier(0);

    size_t                           g_MessageLength = 0;
    std::unique_ptr<MQTT::Message>   g_pMessage; // MQTT messages' lifeline must last until yield occurs for actual transmission.

    // Protect the platform STDIO object so it is shared politely between 
    // threads, periodic events and periodic callbacks (not in IRQ context
    // but when safely translated into the EventQueue context). Essentially,
    // ensure our output does not come out garbled on the serial terminal.
    PlatformMutex                    g_STDIOMutex; 
    EthernetInterface                g_EthernetInterface;
    //NTPClient                        g_NTPClient(&g_EthernetInterface);
    NuerteyNTPClient                 g_NTPClient(&g_EthernetInterface);

    void NetworkStatusCallback(nsapi_event_t status, intptr_t param)
    {
        assert(status == NSAPI_EVENT_CONNECTION_STATUS_CHANGE);

        g_STDIOMutex.lock();
        printf("Network Connection status changed!\r\n");

        switch (param)
        {
        case NSAPI_STATUS_LOCAL_UP:
            printf("Local IP address set!\r\n");
            g_STDIOMutex.unlock();
            break;
        case NSAPI_STATUS_GLOBAL_UP:
            printf("Global IP address set!\r\n");
            g_STDIOMutex.unlock();
            break;
        case NSAPI_STATUS_DISCONNECTED:
            printf("Socket disconnected from network!\r\n");
            g_STDIOMutex.unlock();

            // Since disconnection has been detected, cancel the periodic
            // task of attempting to publish acquired sensor MQTT data.
            if (gs_SensorEventIdentifier)
            {
                gs_MasterEventQueue.cancel(gs_SensorEventIdentifier);
            }

            // TBD, Nuertey Odzeyem; what about cancelling gs_NetworkDisconnectEventIdentifier? cancelAll()??

            // TBD, Nuertey Odzeyem; does the embedded application's
            // requirements necessarily warrant me performing such an action?
            // It is 'embedded' after all and I may just want to 'run forever'.
            gs_MasterEventQueue.break_dispatch();
            break;
        case NSAPI_STATUS_CONNECTING:
            printf("Connecting to network!\r\n");
            g_STDIOMutex.unlock();
            break;
        default:
            printf("Not supported\r\n");
            g_STDIOMutex.unlock();
            break;
        }
    }

    void NetworkDisconnectQuery()
    {
        //printf("About to query if socket disconnected from network!\r\n");

        if (NSAPI_STATUS_DISCONNECTED == g_EthernetInterface.get_connection_status())
        {
            // Since disconnection has been detected, cancel the periodic
            // task of attempting to publish acquired sensor MQTT data.
            if (gs_SensorEventIdentifier)
            {
                g_STDIOMutex.lock();
                printf("Cancelling Sensor Acquisition Event on gs_MasterEventQueue!\r\n");
                g_STDIOMutex.unlock();
                gs_MasterEventQueue.cancel(gs_SensorEventIdentifier);
            }

            // TBD, Nuertey Odzeyem; what about cancelling gs_NetworkDisconnectEventIdentifier? cancelAll()??

            //printf("Breaking gs_MasterEventQueue dispatch!\r\n");

            // TBD, Nuertey Odzeyem; does the embedded application's
            // requirements necessarily warrant me performing such an action?
            // It is 'embedded' after all and I may just want to 'run forever'.
            //gs_MasterEventQueue.break_dispatch();
        }
    }

    // To prevent order of initialization defects.
    bool InitializeGlobalResources()
    {
        // Defensive programming; start from a clean slate.
        g_pMessage.reset();

        randLIB_seed_random();

        //g_pNetworkInterface = NetworkInterface::get_default_instance();
        //
        //if (!g_pNetworkInterface)
        //{
        //    g_STDIOMutex.lock();
        //    printf("FATAL! No network interface found.\n");
        //    g_STDIOMutex.unlock();
        //    return false;
        //}

        // Asynchronously monitor for Network Status events.
        g_EthernetInterface.attach(&NetworkStatusCallback);

        // Use DHCP so that our IP address and other related configuration
        // information such as the subnet mask and default gateway are automatically provided.
        nsapi_size_or_error_t status = g_EthernetInterface.connect();

        if (status < NSAPI_ERROR_OK)
        {
            g_STDIOMutex.lock();
            printf("\r\n\r\nError! g_EthernetInterface.connect() returned: [%d] -> %s\n", status, ToString(status).c_str());
            g_STDIOMutex.unlock();
            return false;
        }
        else
        {
            g_STDIOMutex.lock();
            printf("SUCCESS! Ethernet interface connected successfully!\n");
            g_STDIOMutex.unlock();
            
            //g_NTPClient.set_server("time.google.com", 123);
            //time_t now = g_NTPClient.get_timestamp();
            //set_time(now);
            g_NTPClient.SynchronizeRTCTimestamp();
            std::tie(g_NetworkInterfaceInfo, g_SystemProfile, g_BaseRegisterValues, g_HeapStatistics) = ComposeSystemStatistics();
            return true;
        }
    }

    // For symmetry and to encourage correct and explicit cleanups.
    void ReleaseGlobalResources()
    {
        // Bring down the Ethernet interface.
        g_EthernetInterface.disconnect();
    }
} // namespace

