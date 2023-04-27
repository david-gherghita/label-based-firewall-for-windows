#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

int main(int argc, char* argv[])
{
    if (argc == 1) {
        printf("--- PARENT - %u\n", GetCurrentProcessId());

        // Initialise Winsock
        WSADATA wsaData;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            printf("WSAStartup failed with error: %d\n", iResult);
            return 1;
        }

        // Create socket
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            printf("socket failed (%d)\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Build child cmd
        char childCmd[1000];
        sprintf_s(childCmd, "%s %u", argv[0], (unsigned int)sock);;

        // Create child process
        STARTUPINFOA si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));
        if (!CreateProcessA(
            NULL,
            childCmd,
            NULL,
            NULL,
            TRUE,
            0,
            NULL,
            NULL,
            &si,
            &pi))
        {
            printf("CreateProcessA failed (%d)\n", WSAGetLastError());
            return 1;
        }

        // Wait for the new process to exit
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Close process and thread handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return 0;
    }
    else {
        printf("--- CHILD - %u\n", GetCurrentProcessId());

        // Initialise Winsock
        WSADATA wsaData;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            printf("WSAStartup failed with error: %d\n", iResult);
            return 1;
        }

        // Get socket from parent
        SOCKET sock = (SOCKET)atoi(argv[1]);

        // Prepare the address of the destination.
        SOCKADDR_IN destAddr = {};
        destAddr.sin_family = AF_INET;
        destAddr.sin_port = htons(1337); // Destination port number.
        inet_pton(AF_INET, "192.168.0.101", &(destAddr.sin_addr)); // Destination IP address.

        // Connect to the TCP server
        if(connect(sock, (struct sockaddr*)&destAddr, sizeof(destAddr)) == SOCKET_ERROR) {
            printf("connect failed (%d)\n", WSAGetLastError());
            closesocket(sock);
            WSACleanup();
            return 1;
        }

        // Send a message to the server
        char message1[16] = "Hell0, server!\n";
        send(sock, message1, strlen(message1), 0);

        // Send a message to the server
        char message2[16] = "Hell1, server!\n";
        send(sock, message2, strlen(message2), 0);

        shutdown(sock, 1);

        closesocket(sock);
        WSACleanup();

        return 0;
    }
}
