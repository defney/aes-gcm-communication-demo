#include "session_crypto.h"
#include <iostream>
#include <string>
#include <cstring>
#include <limits>
#include <conio.h>

namespace {
struct Alg {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~Alg() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};
struct Key {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~Key() { if (h) BCryptDestroyKey(h); }
};
struct Secret {
    BCRYPT_SECRET_HANDLE h = nullptr;
    ~Secret() { if (h) BCryptDestroySecret(h); }
};
struct Plain {
    BYTE bytes[64] = {};
    ~Plain() { SecureZeroMemory(bytes, sizeof(bytes)); }
};
bool Random(BYTE* p, ULONG size) {
    return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, p, size,
                         BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}
bool Derive(BCRYPT_SECRET_HANDLE secret, const BYTE context[144],
            const char* direction, BYTE output[32]) {
    BCryptBuffer b[3] = {};
    b[0] = {sizeof(BCRYPT_SHA256_ALGORITHM), KDF_HASH_ALGORITHM,
            const_cast<wchar_t*>(BCRYPT_SHA256_ALGORITHM)};
    b[1] = {144, KDF_SECRET_PREPEND, const_cast<BYTE*>(context)};
    b[2] = {static_cast<ULONG>(std::strlen(direction)), KDF_SECRET_APPEND,
            const_cast<char*>(direction)};
    BCryptBufferDesc desc = {BCRYPTBUFFER_VERSION, 3, b};
    ULONG done = 0;
    return BCRYPT_SUCCESS(BCryptDeriveKey(secret, BCRYPT_KDF_HASH, &desc,
                          output, 32, &done, 0)) && done == 32;
}

// One key per direction. The counter makes nonce reuse impossible in a session.
void SetNonce(uint64_t sequence, BYTE nonce[12]) {
    std::memset(nonce, 0, 12);
    for (int i = 0; i < 8; ++i)
        nonce[4 + i] = static_cast<BYTE>(sequence >> (56 - i * 8));
}
bool Crypt(bool encrypt, const BYTE rawKey[32], EncryptedPasswordMessage& m,
           Plain& plain) {
    Alg alg;
    Key key;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_AES_ALGORITHM,
                                                    nullptr, 0))) return false;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) return false;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg.h, &key.h, nullptr, 0,
                            const_cast<BYTE*>(rawKey), 32, 0))) return false;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = m.nonce; auth.cbNonce = 12;
    auth.pbTag = m.tag; auth.cbTag = 16;
    auth.pbAuthData = reinterpret_cast<BYTE*>(&m); auth.cbAuthData = 16;
    ULONG done = 0;
    NTSTATUS status = encrypt
        ? BCryptEncrypt(key.h, plain.bytes, 64, &auth, nullptr, 0,
                        m.ciphertext, 64, &done, 0)
        : BCryptDecrypt(key.h, m.ciphertext, 64, &auth, nullptr, 0,
                        plain.bytes, 64, &done, 0);
    return BCRYPT_SUCCESS(status) && done == 64;
}
bool Seal(const BYTE key[32], uint64_t seq, uint32_t kind,
          const BYTE* password, size_t size, EncryptedPasswordMessage& out) {
    if (size > 60 || seq == 0 || (kind == RECORD_PASSWORD && size == 0)) return false;
    Plain plain;
    if (!Random(plain.bytes, 64)) return false;
    uint32_t length = static_cast<uint32_t>(size);
    std::memcpy(plain.bytes, &length, 4);
    if (size) std::memcpy(plain.bytes + 4, password, size);
    out = {}; out.version = IPC_VERSION; out.kind = kind; out.sequence = seq;
    SetNonce(seq, out.nonce);
    return Crypt(true, key, out, plain);
}
bool Open(const BYTE key[32], uint64_t expected, EncryptedPasswordMessage& m,
          Plain& plain, uint32_t& length) {
    if (m.version != IPC_VERSION || m.sequence != expected ||
        (m.kind != RECORD_PASSWORD && m.kind != RECORD_CLOSE && m.kind != RECORD_TEST_DONE)) return false;
    BYTE nonce[12]; SetNonce(expected, nonce);
    if (std::memcmp(nonce, m.nonce, 12) != 0 || !Crypt(false, key, m, plain)) return false;
    std::memcpy(&length, plain.bytes, 4);
    return length <= 60 && ((m.kind != RECORD_PASSWORD && length == 0) ||
                            (m.kind == RECORD_PASSWORD && length > 0));
}
volatile LONG stopRequested = 0;
BOOL WINAPI ConsoleControl(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT) {
        InterlockedExchange(&stopRequested, 1); return TRUE;
    }
    return FALSE;
}
enum class Phase { Waiting, AwaitingReply, ReplyPending, Ready, Closed };
struct App {
    bool menu = false, automatic = false, negativeTests = false;
    bool done = false, autoSent = false, gotPassword = false, peerTestDone = false;
    int exitCode = 0;
    Phase phase = Phase::Waiting;
    EcdhSession crypto;
    HWND window = nullptr, peer = nullptr;
    DWORD peerPid = 0;
    uint64_t tx = 0, rx = 0;
    ULONGLONG handshakeStart = 0;
    EncryptedPasswordMessage stored = {}; // Only encrypted received password retained.
    wchar_t input[61] = {};
    size_t inputLength = 0;
    ~App() { SecureZeroMemory(input, sizeof(input)); SecureZeroMemory(&stored, sizeof(stored)); }
    const BYTE* SendKey() const { return menu ? crypto.menuToClientKey : crypto.clientToMenuKey; }
    const BYTE* ReceiveKey() const { return menu ? crypto.clientToMenuKey : crypto.menuToClientKey; }
};
bool MatchesPeer(const App& a, HWND sender) {
    DWORD pid = 0;
    return sender && sender == a.peer && GetWindowThreadProcessId(sender, &pid) && pid == a.peerPid;
}
// -1 transport failure, 0 explicit rejection, 1 accepted.
int SendRaw(App& a, ULONG_PTR type, const void* data, DWORD size) {
    if (!MatchesPeer(a, a.peer)) return -1;
    COPYDATASTRUCT cd = {type, size, const_cast<void*>(data)};
    DWORD_PTR result = 0;
    if (!SendMessageTimeoutW(a.peer, WM_COPYDATA, reinterpret_cast<WPARAM>(a.window),
        reinterpret_cast<LPARAM>(&cd), SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT,
        3000, &result)) return -1;
    return result ? 1 : 0;
}
bool SendPublic(App& a) {
    EcdhPublicKeyMessage msg = {};
    msg.version = IPC_VERSION; msg.senderProcessId = GetCurrentProcessId();
    std::memcpy(msg.publicKey, a.crypto.publicKey, 72);
    return SendRaw(a, IPC_ECDH_PUBLIC_KEY, &msg, sizeof(msg)) == 1;
}
bool SendRecord(App& a, uint32_t kind, const BYTE* data, size_t size) {
    if (a.phase != Phase::Ready || !a.crypto.ready ||
        a.tx == (std::numeric_limits<uint64_t>::max)()) return false;
    EncryptedPasswordMessage m = {};
    if (!Seal(a.SendKey(), a.tx + 1, kind, data, size, m)) return false;
    int result = SendRaw(a, IPC_ENCRYPTED_RECORD, &m, ENCRYPTED_WIRE_SIZE);
    SecureZeroMemory(&m, sizeof(m));
    if (result != 1) {
        // Delivery is ambiguous after a timeout: never reuse this sequence/key.
        a.done = true; a.exitCode = 1; return false;
    }
    ++a.tx;
    return true;
}
void CloseSession(App& a) {
    if (a.phase == Phase::Ready && !SendRecord(a, RECORD_CLOSE, nullptr, 0))
        std::cout << "Kapatma mesaji iletilemedi; yerel anahtarlar temizlenecek.\n";
    a.done = true;
}
LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == WM_NCCREATE) {
        auto cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return TRUE;
    }
    auto a = reinterpret_cast<App*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (!a || message != WM_COPYDATA) return DefWindowProcW(hwnd, message, wParam, lParam);
    auto cd = reinterpret_cast<const COPYDATASTRUCT*>(lParam);
    HWND sender = reinterpret_cast<HWND>(wParam);
    if (!cd || !cd->lpData || a->done) return FALSE;
    if (cd->dwData == IPC_ECDH_PUBLIC_KEY) {
        if (cd->cbData != sizeof(EcdhPublicKeyMessage)) return FALSE;
        EcdhPublicKeyMessage m = {}; std::memcpy(&m, cd->lpData, sizeof(m));
        DWORD pid = 0;
        if (m.version != IPC_VERSION || !sender ||
            !GetWindowThreadProcessId(sender, &pid) || pid != m.senderProcessId ||
            pid == GetCurrentProcessId()) return FALSE;
        // HWND/PID consistency is not cryptographic peer authentication.
        if (a->menu) {
            if (a->phase != Phase::AwaitingReply || !MatchesPeer(*a, sender)) return FALSE;
        } else if (a->phase != Phase::Waiting) return FALSE;
        if (!DeriveSessionKeys(a->crypto, m.publicKey, a->menu)) return FALSE;
        a->peer = sender; a->peerPid = pid;
        a->phase = a->menu ? Phase::Ready : Phase::ReplyPending;
        std::cout << "ECDH anahtarlari turetildi.\n";
        return TRUE;
    }
    if (cd->dwData != IPC_ENCRYPTED_RECORD || cd->cbData != ENCRYPTED_WIRE_SIZE ||
        a->phase != Phase::Ready || !a->crypto.ready || !MatchesPeer(*a, sender) ||
        a->rx == (std::numeric_limits<uint64_t>::max)()) return FALSE;
    EncryptedPasswordMessage m = {}; std::memcpy(&m, cd->lpData, ENCRYPTED_WIRE_SIZE);
    Plain plain; uint32_t length = 0;
    if (!Open(a->ReceiveKey(), a->rx + 1, m, plain, length)) {
        std::cout << "RED: surum/sira/tag/veri dogrulamasi.\n"; return FALSE;
    }
    if (a->automatic && m.kind == RECORD_PASSWORD) {
        const char* expected = a->menu ? "client-test-password" : "menu-test-password";
        if (length != std::strlen(expected) || std::memcmp(plain.bytes + 4, expected, length)) {
            a->exitCode = 1; a->done = true; return FALSE;
        }
    }
    if (m.kind == RECORD_TEST_DONE && (!a->automatic || !a->menu)) return FALSE;
    ++a->rx;
    if (m.kind == RECORD_CLOSE) {
        std::cout << "Dogrulanmis kapatma mesaji alindi.\n";
        a->phase = Phase::Closed; a->done = true;
    } else if (m.kind == RECORD_TEST_DONE) {
        a->peerTestDone = true;
    } else {
        a->stored = m; a->gotPassword = true;
        std::cout << (a->menu ? "Client -> Menu" : "Menu -> Client")
                  << ": parola cozuldu ve tag dogrulandi (" << length << " bayt).\n";
        // KP update belongs here; this demo deliberately does not access a database.
        // Plain is wiped on return; only ciphertext is retained in a->stored.
    }
    return TRUE;
}
bool MakeWindow(App& a, const std::wstring& name) {
    if (FindWindowExW(HWND_MESSAGE, nullptr, name.c_str(), nullptr)) return false;
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc; wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = name.c_str();
    if (!RegisterClassW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;
    a.window = CreateWindowExW(0, name.c_str(), L"", 0, 0, 0, 0, 0,
                              HWND_MESSAGE, nullptr, wc.hInstance, &a);
    return a.window != nullptr;
}
bool AutoSend(App& a) {
    const char* text = a.menu ? "menu-test-password" : "client-test-password";
    EncryptedPasswordMessage original = {};
    if (!Seal(a.SendKey(), a.tx + 1, RECORD_PASSWORD,
              reinterpret_cast<const BYTE*>(text), std::strlen(text), original)) return false;
    if (a.negativeTests) {
        auto bad = original; bad.tag[0] ^= 1;
        if (SendRaw(a, IPC_ENCRYPTED_RECORD, &bad, ENCRYPTED_WIRE_SIZE) != 0) return false;
        bad = original; bad.version = 999;
        if (SendRaw(a, IPC_ENCRYPTED_RECORD, &bad, ENCRYPTED_WIRE_SIZE) != 0) return false;
        bad = original; bad.ciphertext[2] ^= 1;
        if (SendRaw(a, IPC_ENCRYPTED_RECORD, &bad, ENCRYPTED_WIRE_SIZE) != 0) return false;
        if (SendRaw(a, IPC_ENCRYPTED_RECORD, &original, ENCRYPTED_WIRE_SIZE - 1) != 0) return false;
    }
    if (SendRaw(a, IPC_ENCRYPTED_RECORD, &original, ENCRYPTED_WIRE_SIZE) != 1) return false;
    ++a.tx;
    if (a.negativeTests && SendRaw(a, IPC_ENCRYPTED_RECORD, &original, ENCRYPTED_WIRE_SIZE) != 0)
        return false;
    if (a.negativeTests) std::cout << "PASS: bozuk tag/veri, yanlis surum, kisa mesaj, replay reddedildi.\n";
    return true;
}
void PollConsole(App& a) {
    // Nonblocking input: the same thread keeps pumping window messages.
    while (_kbhit()) {
        int ch = _getwch();
        if (ch == 0 || ch == 0xE0) { _getwch(); continue; }
        if (ch == 3) { CloseSession(a); return; }
        if (ch == 8) {
            if (a.inputLength) { a.input[--a.inputLength] = 0; std::cout << "\b \b"; }
            continue;
        }
        if (ch != 13) {
            if (ch >= 32 && a.inputLength < 60) { a.input[a.inputLength++] = static_cast<wchar_t>(ch); std::cout << '*'; }
            continue;
        }
        std::cout << '\n';
        if (std::wcscmp(a.input, L"/quit") == 0) { CloseSession(a); return; }
        Plain utf8;
        int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, a.input,
                    static_cast<int>(a.inputLength), reinterpret_cast<char*>(utf8.bytes), 60, nullptr, nullptr);
        SecureZeroMemory(a.input, sizeof(a.input)); a.inputLength = 0;
        if (a.phase != Phase::Ready) std::cout << "Oturum henuz hazir degil.\n";
        else if (n <= 0) std::cout << "Parola UTF-8 olarak 1-60 bayt olmali.\n";
        else if (SendRecord(a, RECORD_PASSWORD, utf8.bytes, n)) std::cout << "Sifreli parola gonderildi.\n";
        else std::cout << "Gonderim basarisiz; oturum kapaniyor.\n";
    }
}
} // namespace

void ClearEcdhSession(EcdhSession& s) {
    if (s.privateKey) BCryptDestroyKey(s.privateKey);
    if (s.algorithm) BCryptCloseAlgorithmProvider(s.algorithm, 0);
    s.privateKey = nullptr; s.algorithm = nullptr; s.ready = false;
    SecureZeroMemory(s.publicKey, sizeof(s.publicKey));
    SecureZeroMemory(s.menuToClientKey, 32); SecureZeroMemory(s.clientToMenuKey, 32);
}
EcdhSession::~EcdhSession() { ClearEcdhSession(*this); }
bool CreateEcdhSession(EcdhSession& s) {
    ClearEcdhSession(s);
    ULONG size = 0;
    bool ok = BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&s.algorithm, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0)) &&
        BCRYPT_SUCCESS(BCryptGenerateKeyPair(s.algorithm, &s.privateKey, 256, 0)) &&
        BCRYPT_SUCCESS(BCryptFinalizeKeyPair(s.privateKey, 0)) &&
        BCRYPT_SUCCESS(BCryptExportKey(s.privateKey, nullptr, BCRYPT_ECCPUBLIC_BLOB, s.publicKey, 72, &size, 0)) && size == 72;
    if (!ok) ClearEcdhSession(s);
    return ok;
}
bool DeriveSessionKeys(EcdhSession& s, const BYTE peer[72], bool menu) {
    if (!s.algorithm || !s.privateKey || s.ready) return false;
    BCRYPT_ECCKEY_BLOB header = {}; std::memcpy(&header, peer, sizeof(header));
    if (header.dwMagic != BCRYPT_ECDH_PUBLIC_P256_MAGIC || header.cbKey != 32) return false;
    Key imported; Secret secret;
    if (!BCRYPT_SUCCESS(BCryptImportKeyPair(s.algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                            &imported.h, const_cast<BYTE*>(peer), 72, 0)) ||
        !BCRYPT_SUCCESS(BCryptSecretAgreement(s.privateKey, imported.h, &secret.h, 0))) return false;
    BYTE transcript[144];
    std::memcpy(transcript, menu ? s.publicKey : peer, 72);
    std::memcpy(transcript + 72, menu ? peer : s.publicKey, 72);
    bool ok = Derive(secret.h, transcript, "session-v2/menu-to-client", s.menuToClientKey) &&
              Derive(secret.h, transcript, "session-v2/client-to-menu", s.clientToMenuKey);
    if (!ok) { SecureZeroMemory(s.menuToClientKey, 32); SecureZeroMemory(s.clientToMenuKey, 32); }
    else { BCryptDestroyKey(s.privateKey); s.privateKey = nullptr; s.ready = true; }
    return ok;
}

int RunSessionApplication(bool menu, int argc, char** argv) {
    App a; a.menu = menu;
    std::wstring channel = L"default";
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--auto") a.automatic = true;
        else if (arg == "--negative-tests") { a.automatic = true; a.negativeTests = true; }
        else if (arg.rfind("--channel=", 0) == 0 && arg.size() > 10 && arg.size() < 64) {
            std::string suffix = arg.substr(10);
            if (suffix.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != std::string::npos) return 2;
            channel.assign(suffix.begin(), suffix.end());
        } else { std::cerr << "Usage: app1/app2 [--auto] [--negative-tests] [--channel=name]\n"; return 2; }
    }
    std::cout << std::unitbuf;
    std::wstring own = (menu ? L"SessionV2.Menu." : L"SessionV2.Client.") + channel;
    std::wstring other = (menu ? L"SessionV2.Client." : L"SessionV2.Menu.") + channel;
    if (!MakeWindow(a, own)) { std::cerr << "Pencere olusturulamadi veya bu uygulama zaten acik.\n"; return 1; }
    if (!CreateEcdhSession(a.crypto)) { DestroyWindow(a.window); std::cerr << "ECDH olusturulamadi.\n"; return 1; }
    SetConsoleCtrlHandler(ConsoleControl, TRUE);
    std::cout << (menu ? "App1/Menu" : "App2/Client") << " hazir.\n";
    if (menu) {
        a.peer = FindWindowExW(HWND_MESSAGE, nullptr, other.c_str(), nullptr);
        if (!a.peer || !GetWindowThreadProcessId(a.peer, &a.peerPid)) {
            std::cerr << "App2 bulunamadi. Once App2'yi calistir.\n"; a.done = true; a.exitCode = 1;
        } else {
            a.phase = Phase::AwaitingReply; a.handshakeStart = GetTickCount64();
            if (!SendPublic(a)) { a.done = true; a.exitCode = 1; }
        }
    }
    if (!a.automatic) std::cout << "Parola yazip Enter'a basin (gizli giris); kapatmak icin /quit + Enter veya Ctrl+C.\n";
    ULONGLONG start = GetTickCount64();
    while (!a.done) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) { a.done = true; break; }
            TranslateMessage(&msg); DispatchMessageW(&msg);
        }
        if (a.done) break;
        if (InterlockedCompareExchange(&stopRequested, 0, 0)) { CloseSession(a); break; }
        if (a.phase == Phase::ReplyPending) {
            // Respond outside the receiver callback; no console input or nested handshake.
            a.phase = Phase::Ready;
            if (!SendPublic(a)) { a.done = true; a.exitCode = 1; }
        }
        if (a.peer && !MatchesPeer(a, a.peer)) { std::cout << "Karsi uygulama kapandi.\n"; a.done = true; a.exitCode = 1; }
        if (a.phase == Phase::AwaitingReply && GetTickCount64() - a.handshakeStart > 5000) {
            std::cerr << "ECDH cevap zaman asimi.\n"; a.done = true; a.exitCode = 1;
        }
        if (a.done) break;
        if (a.automatic) {
            if (GetTickCount64() - start > 15000) { std::cerr << "Test zaman asimi.\n"; a.done = true; a.exitCode = 1; }
            else if (a.phase == Phase::Ready && !a.autoSent && (menu || a.gotPassword)) {
                a.autoSent = true;
                if (!AutoSend(a) || (!menu && !SendRecord(a, RECORD_TEST_DONE, nullptr, 0))) {
                    std::cerr << "TEST FAIL\n"; a.done = true; a.exitCode = 1;
                }
            } else if (menu && a.autoSent && a.gotPassword && a.peerTestDone) CloseSession(a);
        } else PollConsole(a);
        if (!a.done) MsgWaitForMultipleObjects(0, nullptr, FALSE, 20, QS_ALLINPUT);
    }
    ClearEcdhSession(a.crypto);
    SecureZeroMemory(&a.stored, sizeof(a.stored));
    SecureZeroMemory(a.input, sizeof(a.input));
    DestroyWindow(a.window); SetConsoleCtrlHandler(ConsoleControl, FALSE);
    if (a.automatic && (!a.autoSent || !a.gotPassword)) a.exitCode = 1;
    std::cout << "Oturum kapandi; anahtarlar ve gecici parola alanlari temizlendi.\n";
    return a.exitCode;
}
