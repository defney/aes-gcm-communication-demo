#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

bool BuildPaddedPayload(
    const std::string& password,
    std::vector<BYTE>& payload
)
{
    const size_t PAYLOAD_SIZE = 64;

    // İlk 4 byte gerçek uzunluk için
    if (password.size() > PAYLOAD_SIZE - sizeof(uint32_t))
    {
        std::cout << "Sifre cok uzun.\n";
        return false;
    }

    payload.resize(PAYLOAD_SIZE);

    // Önce tüm buffer'ı random doldur
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        payload.data(),
        static_cast<ULONG>(payload.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!BCRYPT_SUCCESS(status))
    {
        std::cout << "Padding random uretilemedi.\n";
        return false;
    }

    uint32_t length = static_cast<uint32_t>(password.size());

    // İlk 4 byte: şifrenin gerçek uzunluğu
    std::memcpy(
        payload.data(),
        &length,
        sizeof(length)
    );

    // Ardından şifre
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
        std::cout << "KCannot create the key.\n";
        return false;
    }

    std::ofstream file("key.bin", std::ios::binary);

    if (!file)
    {
        std::cout << "cannot open key.bin.\n";
        return false;
    }

    file.write(
        reinterpret_cast<const char*>(key),
        sizeof(key)
    );

    file.close();

    std::cout << "AES-256 key uretildi ve kaydedildi.\n";

    return true;
}
bool LoadKey(BYTE key[32])
{
    std::ifstream file("key.bin", std::ios::binary);

    if (!file)
    {
        std::cout << "key.bin bulunamadi.\n";
        return false;
    }

    file.read(
        reinterpret_cast<char*>(key),
        32
    );

    if (!file)
    {
        std::cout << "Key okunamadi.\n";
        return false;
    }

    return true;
}
bool OpenAESProvider(BCRYPT_ALG_HANDLE& hAlg)
{
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        nullptr,
        0
    );

    if (!BCRYPT_SUCCESS(status))
    {
        std::cout << "AES provider acilamadi.\n";
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
        std::cout << "GCM modu ayarlanamadi.\n";
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    std::cout << "AES-GCM hazir.\n";
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
    // 1. Password + length + random padding olustur
    std::vector<BYTE> payload;

    if (!BuildPaddedPayload(password, payload))
    {
        return false;
    }

    // 2. Her encryption icin yeni nonce
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        nonce,
        12,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!BCRYPT_SUCCESS(status))
    {
        std::cout << "Nonce uretilemedi.\n";
        return false;
    }

    // 3. AES key nesnesi olustur
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
        std::cout << "AES key olusturulamadi.\n";
        return false;
    }

    // 4. AES-GCM bilgileri
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    authInfo.pbNonce = nonce;
    authInfo.cbNonce = 12;

    authInfo.pbTag = tag;
    authInfo.cbTag = 16;

    // payload her zaman 64 byte
    ciphertext.resize(payload.size());

    ULONG encryptedSize = 0;

    // 5. Encrypt
    status = BCryptEncrypt(
        hKey,
        payload.data(),
        static_cast<ULONG>(payload.size()),
        &authInfo,
        nullptr,
        0,
        ciphertext.data(),
        static_cast<ULONG>(ciphertext.size()),
        &encryptedSize,
        0
    );

    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cout << "Encryption basarisiz.\n";
        return false;
    }

    ciphertext.resize(encryptedSize);

    return true;
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
    // 1. Ayni AES key ile key object olustur
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS status = BCryptGenerateSymmetricKey(
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
        std::cout << "Decrypt icin AES key olusturulamadi.\n";
        return false;
    }

    // 2. AES-GCM bilgilerini hazirla
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    authInfo.pbNonce = const_cast<PUCHAR>(nonce);
    authInfo.cbNonce = 12;

    authInfo.pbTag = const_cast<PUCHAR>(tag);
    authInfo.cbTag = 16;

    // Ciphertext 64 byte oldugu icin
    // decrypt sonucu da 64 byte payload olacak
    std::vector<BYTE> plaintext(ciphertext.size());

    ULONG decryptedSize = 0;

    // 3. Decrypt et
    status = BCryptDecrypt(
        hKey,
        const_cast<PUCHAR>(ciphertext.data()),
        static_cast<ULONG>(ciphertext.size()),
        &authInfo,
        nullptr,
        0,
        plaintext.data(),
        static_cast<ULONG>(plaintext.size()),
        &decryptedSize,
        0
    );

    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status))
    {
        std::cout << "Decrypt basarisiz.\n";
        std::cout << "Key, nonce, tag veya ciphertext yanlis olabilir.\n";
        return false;
    }

    // 4. Ilk 4 byte'tan gercek sifre uzunlugunu al
    uint32_t originalLength = 0;

    std::memcpy(
        &originalLength,
        plaintext.data(),
        sizeof(uint32_t)
    );

    // Guvenlik kontrolu
    if (originalLength > decryptedSize - sizeof(uint32_t))
    {
        std::cout << "Payload uzunlugu gecersiz.\n";
        return false;
    }

    // 5. Random padding'i alma.
    // Sadece gercek sifreyi al.
    password.assign(
        reinterpret_cast<char*>(
            plaintext.data() + sizeof(uint32_t)
        ),
        originalLength
    );

    return true;
}

int main()
{
    BYTE key[32];

    // key.bin yoksa olustur
    if (!LoadKey(key))
    {
        std::cout << "Key yok. Yeni AES-256 key olusturuluyor...\n";

        if (!GenerateAndSaveKey())
        {
            return 1;
        }

        if (!LoadKey(key))
        {
            return 1;
        }
    }

    // Kullanici sifresini al
    std::string sifre;

    std::cout << "Sifre gir: ";
    std::getline(std::cin, sifre);

    // AES-GCM provider
    BCRYPT_ALG_HANDLE hAlg = nullptr;

    if (!OpenAESProvider(hAlg))
    {
        return 1;
    }

    // Encrypt sonucunda bunlar olusacak
    std::vector<BYTE> ciphertext;

    BYTE nonce[12];
    BYTE tag[16];

    // Encrypt
    if (!EncryptPassword(
        hAlg,
        key,
        sifre,
        ciphertext,
        nonce,
        tag
    ))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 1;
    }

    // Encrypt edilmis veriyi bas
    std::cout << "\nEncrypted:\n";

    for (BYTE b : ciphertext)
    {
        printf("%02X ", b);
    }

    std::cout << "\n";

    // Kullaniciya decrypt sor
    std::string cevap;

    std::cout << "\nDecrypt etmek ister misin? (ok/no): ";
    std::getline(std::cin, cevap);

    if (cevap == "ok")
    {
        std::string decryptedPassword;

        if (DecryptPassword(
            hAlg,
            key,
            ciphertext,
            nonce,
            tag,
            decryptedPassword
        ))
        {
            std::cout << "\nDecrypted:\n";
            std::cout << decryptedPassword << "\n";
        }
    }
    else
    {
        std::cout << "Decrypt yapilmadi.\n";
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);

    return 0;
}