/*PoC to evade Analysis using a debugger*/

/*
1. Creates a function to check for debugger presence
2. If detected, creates a self-deleting batch file in the temp directory
3. Executes the batch file hidden from view
4. Terminates the application immediately
*/

#include <windows.h>
#include <iostream>

bool SelfDelete() {}
    char path[MAX_PATH];
    // Create batch file to delete executable
    char batPath[MAX_PATH];
    GetTempPathA(MAX_PATH, batpath);
    strcat_s(batpath, "CCleaner.bat"); // batch file name

    File* batch;
    fopen_s(&batch, batPath, "w");
    if (batch) {
        // Wait 3 seconds
        Sleep(3000);
        fprintf(batch, "@echo off\n");
        fprintf(batch, "timeout /t 3 /nobreak >nul\n");
        fprintf(batch, "del \"%s\"\n", path);
        fprintf(batch, "exit\n");
        fclose(batch);

        // Execute the batch file and exit
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        si.dwFlags |= STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        if (CreateProcessA(NULL, batPath, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return true;
        }
    }
    return false;
}

bool IsBeingDebugged() {
    if (IsDebuggerPresent()) {
        std::cout << "Debugger detected. Removing application..." << std::endl;
        SelfDelete();
        ExitProcess(0);
        return true;
    }
    return false;
}

int main() {
    if (IsBeingDebugged()) {
        std::cout << "Debugger detected. Exiting..." << std::endl;
        return 1; // exit 
    }
}