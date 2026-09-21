#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

bool BuildPaddedPayload(
    const std::string& password,
    std::vector<BYTE>& payload
)
{
    const size_t PAYLOAD_SIZE = 64;

    if (password.size() > PAYLOAD_SIZE - sizeof(uint32_t))
    {
        std::cout << "Sifre cok uzun.\n";
        return false;
    }

    payload.resize(PAYLOAD_SIZE);

    // Random padding
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        payload.data(),
        static_cast<ULONG>(payload.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!BCRYPT_SUCCESS(status))
    {
        std::cout << "Padding uretilemedi.\n";
        return false;
    }

    uint32_t length =
        static_cast<uint32_t>(password.size());

    // Ilk 4 byte = gercek uzunluk
    std::memcpy(
        payload.data(),
        &length,
        sizeof(length)
    );

    // Sonra password
    std::memcpy(
        payload.data() + sizeof(length),
        password.data(),
        password.size()
    );

    return true;
}


bool GenerateAndSaveKey()
{
    BYTE key[32];

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        key,
        sizeof(key),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!BCRYPT_SUCCESS(status))
    {
        std::cout << "Key uretilemedi.\n";
        return false;
    }

    std::ofstream file(
        "key.bin",
        std::ios::binary
    );

    if (!file)
    {
        std::cout << "key.bin acilamadi.\n";
        return false;
    }

    file.write(
        reinterpret_cast<const char*>(key),
        sizeof(key)
    );

    return true;
}


bool LoadKey(BYTE key[32])
{
    std::ifstream file(
        "key.bin",
        std::ios::binary
    );

    if (!file)
    {
        return false;
    }

    file.read(
        reinterpret_cast<char*>(key),
        32
    );

    return static_cast<bool>(file);
}


bool OpenAESProvider(
    BCRYPT_ALG_HANDLE& hAlg
)
{
    NTSTATUS status =
        BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_AES_ALGORITHM,
            nullptr,
            0
        );

    if (!BCRYPT_SUCCESS(status))
    {
        return false;
    }

    status = BCryptSetProperty(
        hAlg,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0
    );

    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(
            hAlg,
            0
        );

        return false;
    }

    return true;
}


bool EncryptPassword(
    BCRYPT_ALG_HANDLE hAlg,
    const BYTE key[32],
    const std::string& password,
    std::vector<BYTE>& ciphertext,
    BYTE nonce[12],
    BYTE tag[16]
)
{
    std::vector<BYTE> payload;

    if (!BuildPaddedPayload(
        password,
        payload
    ))
    {
        return false;
    }

    // Her encryption icin yeni nonce
    NTSTATUS status =
        BCryptGenRandom(
            nullptr,
            nonce,
            12,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

    if (!BCRYPT_SUCCESS(status))
    {
        return false;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;

    status = BCryptGenerateSymmetricKey(
        hAlg,
        &hKey,
        nullptr,
        0,
        const_cast<PUCHAR>(key),
        32,
        0
    );

    if (!BCRYPT_SUCCESS(status))
    {
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    authInfo.pbNonce = nonce;
    authInfo.cbNonce = 12;

    authInfo.pbTag = tag;
    authInfo.cbTag = 16;

    ciphertext.resize(
        payload.size()
    );

    ULONG encryptedSize = 0;

    status = BCryptEncrypt(
        hKey,
        payload.data(),
        static_cast<ULONG>(
            payload.size()
        ),
        &authInfo,
        nullptr,
        0,
        ciphertext.data(),
        static_cast<ULONG>(
            ciphertext.size()
        ),
        &encryptedSize,
        0
    );

    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status))
    {
        return false;
    }

    ciphertext.resize(encryptedSize);

    return true;
}


bool SaveEncryptedData(
    const BYTE nonce[12],
    const BYTE tag[16],
    const std::vector<BYTE>& ciphertext
)
{
    std::ofstream file(
        "secret.bin",
        std::ios::binary
    );

    if (!file)
    {
        std::cout
            << "secret.bin acilamadi.\n";

        return false;
    }

    // 12 byte nonce
    file.write(
        reinterpret_cast<const char*>(nonce),
        12
    );

    // 16 byte tag
    file.write(
        reinterpret_cast<const char*>(tag),
        16
    );

    // 64 byte ciphertext
    file.write(
        reinterpret_cast<const char*>(
            ciphertext.data()
        ),
        ciphertext.size()
    );

    return true;
}


int main()
{
    BYTE key[32];

    // Ilk calismada key olustur
    if (!LoadKey(key))
    {
        std::cout
            << "Key yok. Yeni key olusturuluyor...\n";

        if (!GenerateAndSaveKey())
        {
            return 1;
        }

        if (!LoadKey(key))
        {
            return 1;
        }
    }

    std::string password;

    std::cout << "Sifre gir: ";
    std::getline(
        std::cin,
        password
    );

    BCRYPT_ALG_HANDLE hAlg = nullptr;

    if (!OpenAESProvider(hAlg))
    {
        std::cout
            << "AES-GCM acilamadi.\n";

        return 1;
    }

    std::vector<BYTE> ciphertext;

    BYTE nonce[12];
    BYTE tag[16];

    if (!EncryptPassword(
        hAlg,
        key,
        password,
        ciphertext,
        nonce,
        tag
    ))
    {
        std::cout
            << "Encryption basarisiz.\n";

        BCryptCloseAlgorithmProvider(
            hAlg,
            0
        );

        return 1;
    }

    std::cout
        << "\nEncrypted:\n";

    for (BYTE b : ciphertext)
    {
        printf("%02X ", b);
    }

    std::cout << "\n";

    if (!SaveEncryptedData(
        nonce,
        tag,
        ciphertext
    ))
    {
        BCryptCloseAlgorithmProvider(
            hAlg,
            0
        );

        return 1;
    }

    std::cout
        << "\nsecret.bin kaydedildi.\n";

    BCryptCloseAlgorithmProvider(
        hAlg,
        0
    );

    return 0;
}
