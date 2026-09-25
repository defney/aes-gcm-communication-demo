#pragma once

#include <windows.h>
#include <cstdint>

// App1/Menu'nun mesaj almak icin kullanacagi pencere sinifi.
constexpr wchar_t IPC_MENU_WINDOW_CLASS[] =
    L"MenuSessionWindow";

// App2/Client'in mesaj almak icin kullanacagi pencere sinifi.
constexpr wchar_t IPC_CLIENT_WINDOW_CLASS[] =
    L"ClientSessionWindow";
// App1 -> App2:
// AES-GCM ile sifrelenmis parola mesaji.
constexpr ULONG_PTR IPC_ENCRYPTED_PASSWORD =
    0x53504331; // "SPC1"
constexpr ULONG_PTR IPC_CLIENT_PASSWORD =
    0x53504333; // "SPC3"

constexpr ULONG_PTR IPC_CLOSE_SESSION =
    0x53504334; // "SPC4"
// App1 <-> App2:
// ECDH acik anahtar mesaji.
constexpr ULONG_PTR IPC_ECDH_PUBLIC_KEY =
    0x53504332; // "SPC2"

// AES-GCM veri boyutlari.
constexpr size_t IPC_NONCE_SIZE = 12;
constexpr size_t IPC_TAG_SIZE = 16;
constexpr size_t IPC_CIPHERTEXT_SIZE = 64;

// Windows'un ECDH P-256 public-key blob boyutu:
// 8 bayt baslik + 32 bayt X koordinati + 32 bayt Y koordinati.
constexpr size_t IPC_ECDH_P256_PUBLIC_BLOB_SIZE = 72;

// App1'in App2'ye gonderecegi AES-GCM mesaji.
struct EncryptedPasswordMessage
{
    uint32_t version;

    BYTE nonce[IPC_NONCE_SIZE];
    BYTE tag[IPC_TAG_SIZE];
    BYTE ciphertext[IPC_CIPHERTEXT_SIZE];
};

// App1 ve App2'nin birbirine gonderecegi ECDH acik anahtari.
struct EcdhPublicKeyMessage
{
    uint32_t version;
    DWORD senderProcessId;

    BYTE publicKey[
        IPC_ECDH_P256_PUBLIC_BLOB_SIZE
    ];
};

static_assert(
    sizeof(EncryptedPasswordMessage) == 96,
    "Encrypted IPC mesaji 96 bayt olmali."
);

static_assert(
    sizeof(EcdhPublicKeyMessage) == 80,
    "ECDH IPC mesaji 80 bayt olmali."
);