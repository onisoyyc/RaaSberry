/* DLL injection example */

#include <windows.h>
#pragma comment(lib, "user32.lib")

// writing code in DLL main is the simplest solution to get code execution.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD nReason, LPVOID lpReserved) {
    switch (nReason){
        case DLL_PROCESS_ATTACH:
            MessageBox(NULL, "DLL_PROCESS_ATTACH", "DLL Injection", MB_OK);
            break;
        case DLL_PROCESS_DETACH:
            MessageBox(NULL, "DLL_PROCESS_DETACH", "DLL Injection", MB_OK);
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}