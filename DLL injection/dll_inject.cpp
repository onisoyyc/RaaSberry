/* DLL injection example */

#include <windows.h>
#pragma comment(lib, "user32.lib")

BOOL APPENTRY DLLMain(HMODULE hModule, DWORD nReason, LPVOID lpReserved) {
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