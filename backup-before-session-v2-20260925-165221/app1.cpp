#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include "password_auth.h"
#include "ipc_protocol.h"
#include "session_crypto.h"

EcdhSession g_app1Session = {};

bool g_app1SessionReady = false;

bool BuildPaddedPayload(
    const std::string& password,
    std::vector<BYTE>& payload
)
{
    const size_t PAYLOAD_SIZE = 64;

    if (password.size() > PAYLOAD_SIZE - sizeof(uint32_t))
    {
        std::cout << "Password too long.\n";
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
        std::cout << "Cannot create padding.\n";
        return false;
    }
    //lenght as 4 byte
    uint32_t length =
        static_cast<uint32_t>(password.size());

    
    std::memcpy(
        payload.data(),
        &length,
        sizeof(length)
    );
//pasword after length bytes
    std::memcpy(
        payload.data() + sizeof(length),
        password.data(),
        password.size()
    );

    return true;
}
// create key randomly
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
        std::cout << "Key cannot be created.\n";
        return false;
    }

    std::ofstream file(
        "key.bin",
        std::ios::binary
    );

    if (!file)
    {
        std::cout << "Cannot open key.bin\n";
        return false;
    }

    file.write(
        reinterpret_cast<const char*>(key),
        sizeof(key)
    );

    return true;
}

//eger key varsa onu okur byte olarak
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

//aes gcm kullanicak bbilgisini verir ama henuz sifreleme yok 
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
            << "Cannot open secret.bin\n";

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

LRESULT CALLBACK App1WindowProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam
)
{
    if (message != WM_COPYDATA)
    {
        return DefWindowProcW(
            hwnd,
            message,
            wParam,
            lParam
        );
    }

    const COPYDATASTRUCT* copyData =
        reinterpret_cast<
            const COPYDATASTRUCT*
        >(
            lParam
        );

    if (
        copyData == nullptr ||
        copyData->dwData !=
            IPC_ECDH_PUBLIC_KEY ||
        copyData->cbData !=
            sizeof(EcdhPublicKeyMessage) ||
        copyData->lpData == nullptr
    )
    {
        std::cout
            << "App1 gecersiz ECDH cevabi aldi.\n";

        return FALSE;
    }

    const EcdhPublicKeyMessage* response =
        reinterpret_cast<
            const EcdhPublicKeyMessage*
        >(
            copyData->lpData
        );

    if (response->version != 1)
    {
        std::cout
            << "App1 desteklenmeyen ECDH surumu aldi.\n";

        return FALSE;
    }

    if (
        !DeriveSessionKeys(
            g_app1Session,
            response->publicKey
        )
    )
    {
        std::cout
            << "App1 AES oturum anahtarlarini turetemedi.\n";

        return FALSE;
    }

    g_app1SessionReady = true;

    std::cout
        << "App1 ECDH oturumu hazir.\n";

    return TRUE;
}

HWND CreateApp1MessageWindow()
{
    WNDCLASSW windowClass = {};

    windowClass.lpfnWndProc =
        App1WindowProc;

    windowClass.hInstance =
        GetModuleHandleW(nullptr);

    windowClass.lpszClassName =
        IPC_MENU_WINDOW_CLASS;

    ATOM classResult =
        RegisterClassW(&windowClass);

    if (
        classResult == 0 &&
        GetLastError() !=
            ERROR_CLASS_ALREADY_EXISTS
    )
    {
        return nullptr;
    }

    return CreateWindowExW(
        0,
        IPC_MENU_WINDOW_CLASS,
        L"",
        0,
        0,
        0,
        0,
        0,
        HWND_MESSAGE,
        nullptr,
        GetModuleHandleW(nullptr),
        nullptr
    );
}

bool SendApp1PublicKey(
    HWND app2Window,
    HWND app1Window
)
{
    EcdhPublicKeyMessage request = {};

    request.version = 1;

    request.senderProcessId =
        GetCurrentProcessId();

    std::memcpy(
        request.publicKey,
        g_app1Session.publicKey,
        sizeof(request.publicKey)
    );

    COPYDATASTRUCT copyData = {};

    copyData.dwData =
        IPC_ECDH_PUBLIC_KEY;

    copyData.cbData =
        sizeof(request);

    copyData.lpData =
        &request;

    LRESULT accepted =
        SendMessageW(
            app2Window,
            WM_COPYDATA,
            reinterpret_cast<WPARAM>(
                app1Window
            ),
            reinterpret_cast<LPARAM>(
                &copyData
            )
        );

    SecureZeroMemory(
        &request,
        sizeof(request)
    );

    return accepted != FALSE;
}
bool SendEncryptedPasswordToApp2(
    HWND app2Window,
    const std::string& password
)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;

    if (!OpenAESProvider(algorithm))
    {
        std::cout
            << "App1 AES-GCM acilamadi.\n";

        return false;
    }

    std::vector<BYTE> ciphertext;

    BYTE nonce[12] = {};
    BYTE tag[16] = {};

    bool encrypted =
        EncryptPassword(
            algorithm,
            g_app1Session.menuToClientKey,
            password,
            ciphertext,
            nonce,
            tag
        );

    BCryptCloseAlgorithmProvider(
        algorithm,
        0
    );

    if (
        !encrypted ||
        ciphertext.size() !=
            IPC_CIPHERTEXT_SIZE
    )
    {
        SecureZeroMemory(
            nonce,
            sizeof(nonce)
        );

        SecureZeroMemory(
            tag,
            sizeof(tag)
        );

        if (!ciphertext.empty())
        {
            SecureZeroMemory(
                ciphertext.data(),
                ciphertext.size()
            );
        }

        std::cout
            << "App1 parola sifrelenemedi.\n";

        return false;
    }

    EncryptedPasswordMessage message = {};

    message.version = 1;

    std::memcpy(
        message.nonce,
        nonce,
        sizeof(message.nonce)
    );

    std::memcpy(
        message.tag,
        tag,
        sizeof(message.tag)
    );

    std::memcpy(
        message.ciphertext,
        ciphertext.data(),
        sizeof(message.ciphertext)
    );

    COPYDATASTRUCT copyData = {};

    copyData.dwData =
        IPC_ENCRYPTED_PASSWORD;

    copyData.cbData =
        sizeof(message);

    copyData.lpData =
        &message;

    LRESULT accepted =
        SendMessageW(
            app2Window,
            WM_COPYDATA,
            0,
            reinterpret_cast<LPARAM>(
                &copyData
            )
        );

    SecureZeroMemory(
        nonce,
        sizeof(nonce)
    );

    SecureZeroMemory(
        tag,
        sizeof(tag)
    );

    SecureZeroMemory(
        &message,
        sizeof(message)
    );

    SecureZeroMemory(
        ciphertext.data(),
        ciphertext.size()
    );

    return accepted != FALSE;
}
int main()
{
    HWND app1Window =
        CreateApp1MessageWindow();

    if (app1Window == nullptr)
    {
        std::cout
            << "App1 mesaj penceresi olusturulamadi.\n";

        return 1;
    }

    if (!CreateEcdhSession(g_app1Session))
    {
        std::cout
            << "App1 ECDH anahtar cifti olusturulamadi.\n";

        DestroyWindow(app1Window);

        return 1;
    }

    HWND app2Window =
        FindWindowExW(
            HWND_MESSAGE,
            nullptr,
            IPC_CLIENT_WINDOW_CLASS,
            nullptr
        );

    if (app2Window == nullptr)
    {
        std::cout
            << "App2 bulunamadi. Once App2'yi calistir.\n";

        ClearEcdhSession(g_app1Session);

        DestroyWindow(app1Window);

        return 1;
    }

    if (
        !SendApp1PublicKey(
            app2Window,
            app1Window
        )
    )
    {
        std::cout
            << "App1 ECDH mesaji gonderilemedi.\n";

        ClearEcdhSession(g_app1Session);

        DestroyWindow(app1Window);

        return 1;
    }

    if (!g_app1SessionReady)
    {
        std::cout
            << "App2 ECDH cevabi alinamadi.\n";

        ClearEcdhSession(g_app1Session);

        DestroyWindow(app1Window);

        return 1;
    }

std::cout
    << "App1 ve App2 ayni AES oturum anahtarlarini uretti.\n";

std::string password;

std::cout
    << "Gonderilecek parola: ";

std::getline(
    std::cin,
    password
);

if (!std::cin)
{
    std::cout
        << "Parola okunamadi.\n";

    ClearEcdhSession(
        g_app1Session
    );

    DestroyWindow(app1Window);

    return 1;
}

bool sent =
    SendEncryptedPasswordToApp2(
        app2Window,
        password
    );

PasswordAuth::ClearPassword(
    password
);

ClearEcdhSession(
    g_app1Session
);

DestroyWindow(app1Window);

if (!sent)
{
    std::cout
        << "Sifreli parola App2 tarafindan reddedildi.\n";

    return 1;
}

std::cout
    << "Sifreli parola App2'ye gonderildi.\n";

return 0;
}

/* int main(int argc, char* argv[])
{
    // İlk parola kaydı için ayrı çalıştırma:
    // app1.exe --register
    if (argc == 2 && std::string(argv[1]) == "--register")
    {
        std::string password;
        std::string confirmation;

        std::cout << "New password: ";
        std::getline(std::cin, password);

        std::cout << "Enter again: ";
        std::getline(std::cin, confirmation);

        if (!std::cin || password != confirmation)
        {
            PasswordAuth::ClearPassword(password);
            PasswordAuth::ClearPassword(confirmation);

            std::cout << "Passwords are not same.\n";
            return 1;
        }

        bool saved = PasswordAuth::RegisterPassword(password);

        PasswordAuth::ClearPassword(password);
        PasswordAuth::ClearPassword(confirmation);

        std::cout << (
            saved
            ? "Saved.\n"
            : "Not Saved.\n"
        );

        return saved ? 0 : 1;
    }

    if (argc != 1)
    {
        std::cout << "Usage: app1.exe [--register]\n";
        return 1;
    }
    BYTE key[32];

    if (!LoadKey(key))
    {
        std::cout
            << "Key not existing. Creating new key...\n";

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
    if (!PasswordAuth::VerifyPassword(password))
{
    PasswordAuth::ClearPassword(password);

    std::cout << "Password can not verified. stopped.\n";
    return 1;
}

std::cout << "Correct pasaword. Continuing encrption.\n";

    BCRYPT_ALG_HANDLE hAlg = nullptr;

    if (!OpenAESProvider(hAlg))
    {
        std::cout
            << "AES-GCM cannot open.\n";

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
            << "Unsuccesfull encrption.\n";

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
        << "\nsaved secret.bin.\n";


    BCryptCloseAlgorithmProvider(
        hAlg,
        0
    );

    return 0;
}
 */