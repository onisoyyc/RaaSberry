/* PoC for finding a process by name */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

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

    pid = findProcess(argv[1]);
    if (pid) {
        printf("Process %s is running with PID %d\n", argv[1], pid);
    }
    return 0;
}