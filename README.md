# Secure Session IPC Demo

This Windows console demonstration securely exchanges passwords between two local applications:

- **App1 / Menu** starts the session.
- **App2 / Client** accepts the session.

The current application never writes passwords or session keys to disk. Each run creates fresh keys in memory, then transfers encrypted password records through Windows IPC.

## How it works

1. App1 finds the running App2 message window.
2. Both applications generate temporary ECDH P-256 key pairs and exchange public keys through `WM_COPYDATA`.
3. Both sides derive the same shared secret and two different AES-256-GCM keys: one for Menu-to-Client traffic and one for Client-to-Menu traffic.
4. A password entered in either console is UTF-8 encoded, encrypted, authenticated, and sent to the other application.
5. The recipient validates the protocol version, sender, sequence number, nonce, and GCM authentication tag before accepting it.
6. Temporary plaintext buffers and cryptographic keys are cleared when the session closes.

Passwords must be between **1 and 60 UTF-8 bytes**. Console input is masked with `*` characters.

## Required files

| File | Role |
| --- | --- |
| `app1.cpp` | Entry point for App1 / Menu. |
| `app2.cpp` | Entry point for App2 / Client. |
| `session_crypto.h` | Shared session and cryptography declarations. |
| `session_crypto.cpp` | ECDH exchange, AES-GCM encryption, IPC, input, message handling, and cleanup. |
| `ipc_protocol.h` | Versioned IPC message layouts and record-type constants. |
| `test_session.ps1` | Automated integration and negative tests. |

The build produces `app1.exe` and `app2.exe`.

## Requirements

- Windows
- A C++17 compiler; the following examples use MinGW `g++`
- Windows BCrypt and User32 libraries

Close any running copies of `app1.exe` and `app2.exe` before rebuilding.

## Build

Open PowerShell in this directory and run:

```powershell
g++ -std=c++17 -Wall -Wextra app1.cpp session_crypto.cpp -o app1.exe -lbcrypt -luser32 -static-libgcc -static-libstdc++
g++ -std=c++17 -Wall -Wextra app2.cpp session_crypto.cpp -o app2.exe -lbcrypt -luser32 -static-libgcc -static-libstdc++
```

## Run interactively

Open two PowerShell windows in the project directory.

Start **App2 first**:

```powershell
.\app2.exe
```

Then start App1 in the second window:

```powershell
.\app1.exe
```

When the handshake has completed, type a password in either console and press Enter. The other application confirms that it decrypted and authenticated a password but does not print the plaintext.

Enter `/quit` and press Enter in either application, or press Ctrl+C, to close the session.

## Command-line options

```text
--auto
--negative-tests
--channel=<name>
```

- `--auto` sends fixed test passwords automatically in both directions.
- `--negative-tests` also tests rejection of altered tags/ciphertext, bad versions, malformed messages, and replayed messages.
- `--channel=<name>` selects an isolated communication channel. Both applications must use the same channel name; names allow letters, digits, and `-`.

Example negative test:

```powershell
# First window
.\app2.exe --negative-tests --channel=demo

# Second window
.\app1.exe --negative-tests --channel=demo
```

## Automated tests

The test script runs regular and negative round-trip tests, verifies a missing-peer case, and confirms that legacy disk files are not created or changed:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\test_session.ps1
```

## Security notes and limitations

- Fresh ECDH P-256 keys are generated for every session; no session key is stored persistently.
- The shared secret is expanded with a SHA-256 KDF into separate AES-256-GCM keys for the two directions.
- Each direction uses increasing sequence numbers to derive GCM nonces, preventing nonce reuse and rejecting replayed messages.
- The packet header is authenticated as AES-GCM additional authenticated data (AAD).
- `SendMessageTimeoutW` prevents an indefinite wait for an unresponsive peer.
- Window-handle and process-ID checks are consistency checks, **not cryptographic peer authentication**. A production system needs a trusted launch and identity/authentication mechanism.
- Clearing buffers reduces accidental retention but cannot fully protect against memory dumps, paging, or a privileged process reading memory.

