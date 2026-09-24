#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <iostream>
#include <string>
#include <cstring>

namespace PasswordAuth
{
    // Dosyada açık parola değil, salt ve parola özeti bulunur.
    constexpr char FILE_NAME[] = "password.verifier";
    constexpr ULONGLONG ITERATIONS = 600000;

    inline void ClearPassword(std::string& password)
    {
        if (!password.empty())
            SecureZeroMemory(&password[0], password.size());

        password.clear();
    }

    // Paroladan 32 baytlık bir doğrulama özeti üretir.
    // Bu işlem şifreleme değildir; geri çözülmez.
    inline bool HashPassword(
        const std::string& password,
        BYTE salt[16],
        BYTE output[32])
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &algorithm,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            BCRYPT_ALG_HANDLE_HMAC_FLAG
        );

        if (!BCRYPT_SUCCESS(status))
            return false;

        status = BCryptDeriveKeyPBKDF2(
            algorithm,
            reinterpret_cast<PUCHAR>(
                const_cast<char*>(password.data())
            ),
            static_cast<ULONG>(password.size()),
            salt,
            16,
            ITERATIONS,
            output,
            32,
            0
        );

        BCryptCloseAlgorithmProvider(algorithm, 0);

        return BCRYPT_SUCCESS(status);
    }

    // Yalnızca ilk kurulumda çağrılır.
    inline bool RegisterPassword(const std::string& password)
    {
        // Mevcut şifreli mesaj biçiminin sınırı: 60 bayt.
        if (password.empty() || password.size() > 60)
        {
            std::cout << "Parola 1-60 bayt olmali.\n";
            return false;
        }

        // 8 bayt sürüm + 16 bayt salt + 32 bayt özet
        BYTE record[56] = {};
        std::memcpy(record, "PWDv0001", 8);

        NTSTATUS status = BCryptGenRandom(
            nullptr,
            record + 8,
            16,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

        if (!BCRYPT_SUCCESS(status))
            return false;

        if (!HashPassword(password, record + 8, record + 24))
        {
            SecureZeroMemory(record, sizeof(record));
            return false;
        }

        // CREATE_NEW: mevcut parola kaydının üzerine yazma.
        HANDLE file = CreateFileA(
            FILE_NAME,
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (file == INVALID_HANDLE_VALUE)
        {
            std::cout
                << "Kayit olusturulamadi; kayit zaten mevcut olabilir.\n";

            SecureZeroMemory(record, sizeof(record));
            return false;
        }

        DWORD written = 0;

        bool success =
            WriteFile(
                file,
                record,
                sizeof(record),
                &written,
                nullptr
            ) != 0 &&
            written == sizeof(record);

        if (success)
            success = FlushFileBuffers(file) != 0;

        CloseHandle(file);
        SecureZeroMemory(record, sizeof(record));

        if (!success)
            DeleteFileA(FILE_NAME);

        return success;
    }

    // Girilen parolayı mevcut kayıtla karşılaştırır.
    inline bool VerifyPassword(const std::string& password)
    {
        if (password.empty() || password.size() > 60)
            return false;

        BYTE record[56] = {};

        std::ifstream file(FILE_NAME, std::ios::binary);

        file.read(
            reinterpret_cast<char*>(record),
            sizeof(record)
        );

        // Eksik, fazla uzun veya tanınmayan kayıtları reddet.
        if (!file ||
            file.peek() != std::char_traits<char>::eof() ||
            std::memcmp(record, "PWDv0001", 8) != 0)
        {
            std::cout << "Parola kaydi yok veya bozuk.\n";
            return false;
        }

        BYTE calculatedHash[32] = {};

        bool success = HashPassword(
            password,
            record + 8,
            calculatedHash
        );

        // İlk farklı baytta durmadan bütün özeti karşılaştır.
        volatile unsigned int difference = 0;

        for (size_t i = 0; i < sizeof(calculatedHash); ++i)
            difference |= calculatedHash[i] ^ record[24 + i];

        SecureZeroMemory(calculatedHash, sizeof(calculatedHash));
        SecureZeroMemory(record, sizeof(record));

        return success && difference == 0;
    }
}