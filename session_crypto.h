#pragma once
#include "ipc_protocol.h"
#include <bcrypt.h>

struct EcdhSession {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE privateKey = nullptr;
    BYTE publicKey[72] = {};
    BYTE menuToClientKey[32] = {};
    BYTE clientToMenuKey[32] = {};
    bool ready = false;
    EcdhSession() = default;
    EcdhSession(const EcdhSession&) = delete;
    EcdhSession& operator=(const EcdhSession&) = delete;
    ~EcdhSession();
};
bool CreateEcdhSession(EcdhSession& s);
bool DeriveSessionKeys(EcdhSession& s, const BYTE peer[72], bool isMenu);
void ClearEcdhSession(EcdhSession& s);
// Shared implementation: each executable still owns its own independent state.
int RunSessionApplication(bool isMenu, int argc, char** argv);
