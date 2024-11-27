#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

DWORD PID = NULL; 
HANDLE hProcess = NULL;
HANDLE hThread = NULL;


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
    hProcess = OpenProcess( //open handle to process pid
        PROCESS_ALL_ACCESS,
        FALSE,
        PID
    );
    if (hProcess == NULL) {
        //GetLastError();
        return EXIT_FAILURE;
    };
    // Allocate a buffer in the process memory with the necessary permissions

    //Write the contents of the shellcode to that buffer in the process memory

    //Create a thread that will run in allocated memory and written into the process
    
    return EXIT_SUCCESS;

}
