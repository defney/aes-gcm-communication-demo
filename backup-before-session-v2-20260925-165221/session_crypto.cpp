#include "session_crypto.h"
#include <cstring>

void ClearEcdhSession(
    EcdhSession& session
)
{
    if (session.sharedSecret != nullptr)
    {
        BCryptDestroySecret(
            session.sharedSecret
        );
    }

    if (session.privateKey != nullptr)
    {
        BCryptDestroyKey(
            session.privateKey
        );
    }

    if (session.algorithm != nullptr)
    {
        BCryptCloseAlgorithmProvider(
            session.algorithm,
            0
        );
    }

    SecureZeroMemory(
        &session,
        sizeof(session)
    );
}


bool CreateEcdhSession(
    EcdhSession& session
)

{
    ClearEcdhSession(session);

    NTSTATUS status =
        BCryptOpenAlgorithmProvider(
            &session.algorithm,
            BCRYPT_ECDH_P256_ALGORITHM,
            nullptr,
            0
        );

    if (!BCRYPT_SUCCESS(status))
    {
        return false;
    }

    status = BCryptGenerateKeyPair(
        session.algorithm,
        &session.privateKey,
        256,
        0
    );

    if (!BCRYPT_SUCCESS(status))
    {
        ClearEcdhSession(session);

        return false;
    }

    status = BCryptFinalizeKeyPair(
        session.privateKey,
        0
    );

    if (!BCRYPT_SUCCESS(status))
    {
        ClearEcdhSession(session);

        return false;
    }

    ULONG exportedSize = 0;

    status = BCryptExportKey(
        session.privateKey,
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        session.publicKey,
        sizeof(session.publicKey),
        &exportedSize,
        0
    );

    if (
        !BCRYPT_SUCCESS(status) ||
        exportedSize != sizeof(session.publicKey)
    )
    {
        ClearEcdhSession(session);

        return false;
    }

    return true;
}

// ECDH ortak sırrından, verilen yon etiketi icin
// 32 baytlik AES-256 anahtari turetir.
bool DeriveOneAesKey(
    BCRYPT_SECRET_HANDLE sharedSecret,
    const char* directionLabel,
    BYTE outputKey[32]
)
{
    BCryptBuffer buffers[2] = {};
    buffers[0].BufferType =
        KDF_HASH_ALGORITHM;

    buffers[0].cbBuffer =
        sizeof(BCRYPT_SHA256_ALGORITHM);

    buffers[0].pvBuffer =
        const_cast<wchar_t*>(
            BCRYPT_SHA256_ALGORITHM
        );

    buffers[1].BufferType =
        KDF_SECRET_APPEND;

    buffers[1].cbBuffer =
        static_cast<ULONG>(
            std::strlen(directionLabel)
        );

    buffers[1].pvBuffer =
        const_cast<char*>(
            directionLabel
        );

    BCryptBufferDesc parameters = {};

    parameters.ulVersion =
        BCRYPTBUFFER_VERSION;

    parameters.cBuffers = 2;

    parameters.pBuffers = buffers;

    ULONG derivedSize = 0;

    NTSTATUS status =
        BCryptDeriveKey(
            sharedSecret,
            BCRYPT_KDF_HASH,
            &parameters,
            outputKey,
            32,
            &derivedSize,
            0
        );

    return
        BCRYPT_SUCCESS(status) &&
        derivedSize == 32;
}

bool DeriveSessionKeys(
    EcdhSession& session,
    const BYTE peerPublicKey[
        IPC_ECDH_P256_PUBLIC_BLOB_SIZE
    ]
)
{
    if (
        session.algorithm == nullptr ||
        session.privateKey == nullptr
    )
    {
        return false;
    }

    BCRYPT_KEY_HANDLE peerKey = nullptr;

    NTSTATUS status =
        BCryptImportKeyPair(
            session.algorithm,
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            &peerKey,
            const_cast<PUCHAR>(
                peerPublicKey
            ),
            IPC_ECDH_P256_PUBLIC_BLOB_SIZE,
            0
        );

    if (!BCRYPT_SUCCESS(status))
    {
        return false;
    }

    if (session.sharedSecret != nullptr)
    {
        BCryptDestroySecret(
            session.sharedSecret
        );

        session.sharedSecret = nullptr;
    }

    status = BCryptSecretAgreement(
        session.privateKey,
        peerKey,
        &session.sharedSecret,
        0
    );

    BCryptDestroyKey(peerKey);

    if (!BCRYPT_SUCCESS(status))
    {
        session.sharedSecret = nullptr;

        return false;
    }

    bool menuToClientOk =
        DeriveOneAesKey(
            session.sharedSecret,
            "menu-to-client-v1",
            session.menuToClientKey
        );

    bool clientToMenuOk =
        DeriveOneAesKey(
            session.sharedSecret,
            "client-to-menu-v1",
            session.clientToMenuKey
        );

    if (
        !menuToClientOk ||
        !clientToMenuOk
    )
    {
        SecureZeroMemory(
            session.menuToClientKey,
            sizeof(session.menuToClientKey)
        );

        SecureZeroMemory(
            session.clientToMenuKey,
            sizeof(session.clientToMenuKey)
        );

        return false;
    }

    return true;
}