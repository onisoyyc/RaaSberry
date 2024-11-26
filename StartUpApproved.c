
/*
Establish persistence on victim machine
Will create a message box to end user telling them their system has been locked
Step 3 in Attack Chain
*/

#include <widnows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD, nReason, LVPOID lpReserved){ // dll entry point
    switch (nReason){
        case DLL_PROCESS_ATTACH:
            MessageBox(
                NULL, 
                "You've been Raspberried!", // consult with group for official message
                "<Evil Laugh>",
                MD_OK
            );
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}