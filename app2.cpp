#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>


bool LoadKey(BYTE key[32])
{
    std::ifstream file(
        "key.bin",
        std::ios::binary
    );

    if (!file)
    {
        std::cout
            << "key.bin bulunamadi.\n";

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


bool LoadEncryptedData(
    BYTE nonce[12],
    BYTE tag[16],
    std::vector<BYTE>& ciphertext
)
{
    std::ifstream file(
        "secret.bin",
        std::ios::binary
    );

    if (!file)
    {
        std::cout
            << "secret.bin bulunamadi.\n";

        return false;
    }

    // nonce
    file.read(
        reinterpret_cast<char*>(nonce),
        12
    );

    // tag
    file.read(
        reinterpret_cast<char*>(tag),
        16
    );

    // Bizim payload sabit 64 byte
    ciphertext.resize(64);

    file.read(
        reinterpret_cast<char*>(
            ciphertext.data()
        ),
        ciphertext.size()
    );

    return static_cast<bool>(file);
}


bool DecryptPassword(
    BCRYPT_ALG_HANDLE hAlg,
    const BYTE key[32],
    const std::vector<BYTE>& ciphertext,
    const BYTE nonce[12],
    const BYTE tag[16],
    std::string& password
)
{
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS status =
        BCryptGenerateSymmetricKey(
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

    authInfo.pbNonce =
        const_cast<PUCHAR>(nonce);

    authInfo.cbNonce = 12;

    authInfo.pbTag =
        const_cast<PUCHAR>(tag);

    authInfo.cbTag = 16;

    std::vector<BYTE> plaintext(
        ciphertext.size()
    );

    ULONG decryptedSize = 0;

    status = BCryptDecrypt(
        hKey,
        const_cast<PUCHAR>(
            ciphertext.data()
        ),
        static_cast<ULONG>(
            ciphertext.size()
        ),
        &authInfo,
        nullptr,
        0,
        plaintext.data(),
        static_cast<ULONG>(
            plaintext.size()
        ),
        &decryptedSize,
        0
    );

    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cout
            << "Decrypt basarisiz.\n";

        return false;
    }

    // Ilk 4 byte -> gerçek uzunluk
    uint32_t originalLength = 0;

    std::memcpy(
        &originalLength,
        plaintext.data(),
        sizeof(uint32_t)
    );

    if (
        originalLength >
        decryptedSize - sizeof(uint32_t)
    )
    {
        std::cout
            << "Payload gecersiz.\n";

        return false;
    }

    password.assign(
        reinterpret_cast<char*>(
            plaintext.data()
            + sizeof(uint32_t)
        ),
        originalLength
    );

    return true;
}


int main()
{
    BYTE key[32];

    if (!LoadKey(key))
    {
        return 1;
    }

    BYTE nonce[12];
    BYTE tag[16];

    std::vector<BYTE> ciphertext;

    if (!LoadEncryptedData(
        nonce,
        tag,
        ciphertext
    ))
    {
        return 1;
    }

    std::cout
        << "Encrypted:\n";

    for (BYTE b : ciphertext)
    {
        printf("%02X ", b);
    }

    std::cout << "\n";

    BCRYPT_ALG_HANDLE hAlg = nullptr;

    if (!OpenAESProvider(hAlg))
    {
        return 1;
    }

    std::string password;

    if (!DecryptPassword(
        hAlg,
        key,
        ciphertext,
        nonce,
        tag,
        password
    ))
    {
        BCryptCloseAlgorithmProvider(
            hAlg,
            0
        );

        return 1;
    }

    std::cout
        << "\nDecrypted:\n";

    std::cout
        << password
        << "\n";

    BCryptCloseAlgorithmProvider(
        hAlg,
        0
    );

    return 0;
}
