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
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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
        inet_pton(AF_INET, "127.0.0.1", &(destAddr.sin_addr)); // Destination IP address.

        // Send a UDP datagram.
        const char* message = "Hello, world!";
        int messageLen = (int)strlen(message);
        int bytesSent = sendto(sock, message, messageLen, 0, (SOCKADDR*)&destAddr, sizeof(destAddr));
        if (bytesSent == SOCKET_ERROR)
        {
            printf("sendto failed (%d)\n", WSAGetLastError());
            closesocket(sock);
            WSACleanup();
            return 1;
        }

        return 0;
    }
}
