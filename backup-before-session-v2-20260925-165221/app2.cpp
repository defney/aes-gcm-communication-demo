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

EcdhSession g_app2Session = {};

bool LoadKey(BYTE key[32])
{
    std::ifstream file(
        "key.bin",
        std::ios::binary
    );

    if (!file)
    {
        std::cout
            << "key.bin not found.\n";

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
            << "cannot find secret.bin.\n";

        return false;
    }

    file.read(
        reinterpret_cast<char*>(nonce),
        12
    );

    file.read(
        reinterpret_cast<char*>(tag),
        16
    );

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
            << "Decrypt unsuccesfull.\n";

        return false;
    }

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
            << "Unvalid Payload.\n";

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
bool SendApp2PublicKey(
    HWND app1Window,
    HWND app2Window
)
{
    EcdhPublicKeyMessage response = {};

    response.version = 1;

    response.senderProcessId =
        GetCurrentProcessId();

    std::memcpy(
        response.publicKey,
        g_app2Session.publicKey,
        sizeof(response.publicKey)
    );

    COPYDATASTRUCT copyData = {};

    copyData.dwData =
        IPC_ECDH_PUBLIC_KEY;

    copyData.cbData =
        sizeof(response);

    copyData.lpData =
        &response;

    LRESULT accepted =
        SendMessageW(
            app1Window,
            WM_COPYDATA,
            reinterpret_cast<WPARAM>(
                app2Window
            ),
            reinterpret_cast<LPARAM>(
                &copyData
            )
        );

    SecureZeroMemory(
        &response,
        sizeof(response)
    );

    return accepted != FALSE;
}
constexpr wchar_t RECEIVER_WINDOW_CLASS[] =
    L"PasswordReceiverWindow";

LRESULT CALLBACK ReceiverWindowProc(
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
        copyData->lpData == nullptr
    )
    {
        std::cout
            << "Gecersiz IPC mesaji geldi.\n";

        return FALSE;
    }

    if (
        copyData->dwData ==
        IPC_ECDH_PUBLIC_KEY
    )
    {
        if (
            copyData->cbData !=
            sizeof(EcdhPublicKeyMessage)
        )
        {
            std::cout
                << "ECDH mesaj boyutu gecersiz.\n";

            return FALSE;
        }

        const EcdhPublicKeyMessage* request =
            reinterpret_cast<
                const EcdhPublicKeyMessage*
            >(
                copyData->lpData
            );

        if (request->version != 1)
        {
            std::cout
                << "ECDH mesaj surumu desteklenmiyor.\n";

            return FALSE;
        }

        if (
            !DeriveSessionKeys(
                g_app2Session,
                request->publicKey
            )
        )
        {
            std::cout
                << "App2 ortak oturum anahtarlarini uretemedi.\n";

            return FALSE;
        }

        HWND app1Window =
            reinterpret_cast<HWND>(
                wParam
            );

        if (app1Window == nullptr)
        {
            std::cout
                << "App1 pencere bilgisi yok.\n";

            return FALSE;
        }

        if (
            !SendApp2PublicKey(
                app1Window,
                hwnd
            )
        )
        {
            std::cout
                << "App2 ECDH cevabi gonderilemedi.\n";

            return FALSE;
        }

        std::cout
            << "App2 ECDH oturumu hazir.\n";

        return TRUE;
    }

if (
    copyData->dwData ==
    IPC_ENCRYPTED_PASSWORD
)
{
    if (
        copyData->cbData !=
        sizeof(EncryptedPasswordMessage)
    )
    {
        std::cout
            << "Sifreli parola mesaj boyutu gecersiz.\n";

        return FALSE;
    }

    const EncryptedPasswordMessage* encrypted =
        reinterpret_cast<
            const EncryptedPasswordMessage*
        >(
            copyData->lpData
        );

    if (encrypted->version != 1)
    {
        std::cout
            << "Sifreli parola mesaj surumu desteklenmiyor.\n";

        return FALSE;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;

    if (!OpenAESProvider(algorithm))
    {
        std::cout
            << "App2 AES-GCM acilamadi.\n";

        return FALSE;
    }

    std::vector<BYTE> ciphertext(
        encrypted->ciphertext,
        encrypted->ciphertext +
            sizeof(encrypted->ciphertext)
    );

    std::string password;

    bool decrypted =
        DecryptPassword(
            algorithm,
            g_app2Session.menuToClientKey,
            ciphertext,
            encrypted->nonce,
            encrypted->tag,
            password
        );

    SecureZeroMemory(
        ciphertext.data(),
        ciphertext.size()
    );

    BCryptCloseAlgorithmProvider(
        algorithm,
        0
    );

    if (!decrypted)
    {
        std::cout
            << "App2 AES-GCM geri cozme veya tag dogrulamasi basarisiz.\n";

        return FALSE;
    }

    std::cout
        << "App2 sifreli parolayi geri cozdu: "
        << password
        << "\n";

    PasswordAuth::ClearPassword(
        password
    );

    return TRUE;
}

    std::cout
        << "Bilinmeyen IPC mesaji geldi.\n";

    return FALSE;
}
HWND CreateMessageReceiverWindow()
{
    WNDCLASSW windowClass = {};

    windowClass.lpfnWndProc =
        ReceiverWindowProc;

    windowClass.hInstance =
        GetModuleHandleW(nullptr);

    windowClass.lpszClassName =
        IPC_CLIENT_WINDOW_CLASS;

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
        IPC_CLIENT_WINDOW_CLASS,
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
int main()
{
    HWND receiverWindow =
        CreateMessageReceiverWindow();

    if (receiverWindow == nullptr)
    {
        std::cout
            << "Mesaj alici penceresi olusturulamadi.\n";

        return 1;
    }

    if (!CreateEcdhSession(g_app2Session))
    {
        std::cout
            << "App2 ECDH anahtar cifti olusturulamadi.\n";

        DestroyWindow(receiverWindow);

        return 1;
    }

    std::cout
        << "App2 hazir. ECDH acik anahtari RAM'de olusturuldu.\n";

    std::cout
        << "App1'den ECDH mesaji bekleniyor...\n";

    MSG message = {};

    while (
        GetMessageW(
            &message,
            nullptr,
            0,
            0
        ) > 0
    )
    {
        TranslateMessage(&message);

        DispatchMessageW(&message);
    }

    ClearEcdhSession(
        g_app2Session
    );

    return 0;
}

/* int main()
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
    if (!PasswordAuth::VerifyPassword(password))
{
    PasswordAuth::ClearPassword(password);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    std::cout << "Passwords not match.\n";
    return 1;
}

std::cout << "Checked.\n";
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
 */