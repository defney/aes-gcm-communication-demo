#pragma once
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <cstdint>
#include <cstddef>

// Version 2: sequence and message kind are authenticated with AES-GCM.
constexpr uint32_t IPC_VERSION = 2;
constexpr ULONG_PTR IPC_ECDH_PUBLIC_KEY = 0x53504332;
constexpr ULONG_PTR IPC_ENCRYPTED_RECORD = 0x53504335;
constexpr uint32_t RECORD_PASSWORD = 1;
constexpr uint32_t RECORD_CLOSE = 2;
constexpr uint32_t RECORD_TEST_DONE = 3;
constexpr size_t IPC_ECDH_P256_PUBLIC_BLOB_SIZE = 72;

struct EcdhPublicKeyMessage {
    uint32_t version;
    uint32_t senderProcessId;
    BYTE publicKey[72];
};
struct EncryptedPasswordMessage {
    uint32_t version;
    uint32_t kind;
    uint64_t sequence;
    BYTE nonce[12];
    BYTE tag[16];
    BYTE ciphertext[64];
};
static_assert(sizeof(EcdhPublicKeyMessage) == 80, "ECDH layout");
static_assert(offsetof(EncryptedPasswordMessage, nonce) == 16, "AAD layout");
// 108 meaningful bytes; struct tail padding is never transmitted.
constexpr DWORD ENCRYPTED_WIRE_SIZE = 108;
