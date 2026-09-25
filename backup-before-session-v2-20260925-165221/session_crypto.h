#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <cstdint>

#include "ipc_protocol.h"

// Bir uygulamanin kendi ECDH oturum bilgisini tutar.
struct EcdhSession
{
    // Windows'ta ECDH algoritmasina erisim referansi.
    BCRYPT_ALG_HANDLE algorithm = nullptr;

    // Bu uygulamanin gizli ECDH anahtarini tutan Windows nesnesi.
    BCRYPT_KEY_HANDLE privateKey = nullptr;

    // App1 ve App2'nin ortak ECDH sirri.
    BCRYPT_SECRET_HANDLE sharedSecret = nullptr;

    // Bu uygulamanin diger tarafa gonderecegi acik ECDH anahtari.
    BYTE publicKey[
        IPC_ECDH_P256_PUBLIC_BLOB_SIZE
    ] = {};

    // Menu -> Client yonundeki AES-256 anahtari.
    BYTE menuToClientKey[32] = {};

    // Client -> Menu yonundeki AES-256 anahtari.
    BYTE clientToMenuKey[32] = {};
};

// Bu uygulama icin gecici ECDH anahtar cifti olusturur.
bool CreateEcdhSession(
    EcdhSession& session
);

// Karsi tarafin acik anahtarini kullanarak
// iki AES-256 oturum anahtari turetir.
bool DeriveSessionKeys(
    EcdhSession& session,
    const BYTE peerPublicKey[
        IPC_ECDH_P256_PUBLIC_BLOB_SIZE
    ]
);

// Windows nesnelerini ve hassas bellek alanlarini temizler.
void ClearEcdhSession(
    EcdhSession& session
);