#include <iostream>
#include <string>
#include <cstdio>
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

bool randomBytes(unsigned char* buf, DWORD n) {
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return false;
    bool ok = CryptGenRandom(hProv, n, buf) == TRUE;
    CryptReleaseContext(hProv, 0);
    return ok;
}

std::string createKey() {
    std::string key = "";
    char buf[32];
    while (key.size() != 16) {
        unsigned char b[3];
        randomBytes(b, 3);
        unsigned char v1 = b[0];
        unsigned char v2 = b[1];
        unsigned char v3m = b[2] % 255;
        snprintf(buf, sizeof(buf), "%02X%02X%02X7C%02X%02X%02X%02X",
            v1, v2 ^ 0x7C, 0xFF ^ v1, v2, v3m, v3m ^ 7, v1 ^ (0xFF ^ v3m));
        key = std::string(buf);
    }
    return key;
}

std::string getAppVersion() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\MadeForNet\\HTTPDebuggerPro",
        0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) {
        std::cerr << "Error: could not open HTTPDebuggerPro registry key\n";
        return "";
    }
    char value[256] = {};
    DWORD size = sizeof(value);
    RegQueryValueExA(hKey, "AppVer", NULL, NULL, (LPBYTE)value, &size);
    RegCloseKey(hKey);

    std::string digits;
    for (char c : std::string(value))
        if (isdigit(c)) digits += c;
    return digits;
}

std::string getSerialNumber(const std::string& appVersion) {
    DWORD volumeSerial = 0;
    GetVolumeInformationW(L"C:\\", NULL, 0, &volumeSerial, NULL, NULL, NULL, 0);
    uint32_t value = (uint32_t)std::stoul(appVersion);
    uint32_t sn = value ^ ((~volumeSerial >> 1) + 0x2E0) ^ 0x590D4;
    return std::to_string((int32_t)sn);
}

void writeKey(const std::string& sn, const std::string& key) {
    HKEY hKey;
    RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\MadeForNet\\HTTPDebuggerPro",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    std::string valueName = "SN" + sn;
    RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ,
        (const BYTE*)key.c_str(), (DWORD)key.size() + 1);
    RegCloseKey(hKey);
}

int main() {
    std::cout << "=== HTTPDebugger Keygen ===\n\n";

    std::string av = getAppVersion();
    if (av.empty()) {
        std::cout << "\nPress any key to exit...";
        std::cin.get();
        return 1;
    }

    std::string sn = getSerialNumber(av);
    std::string key = createKey();

    std::cout << "App Version:   " << av << "\n";
    std::cout << "Serial Number: " << sn << "\n";
    std::cout << "Key:           " << key << "\n\n";

    writeKey(sn, key);
    std::cout << "Registry key written: HKCU\\SOFTWARE\\MadeForNet\\HTTPDebuggerPro\\SN" << sn << "\n";

    std::cout << "\nPress any key to exit...";
    std::cin.get();
    return 0;
}
