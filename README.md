# CredShell

**Local-First, Zero-Crate, Zero-Daemon TOTP & WebAuthn Passkey Authenticator**

CredShell is a high-security, high-performance vault authenticator written in pure Rust with **zero external dependencies** (`dependencies = []`). It provides an encrypted local vault for RFC 6238 TOTP two-factor codes and acts as a native WebAuthn Level 3 Passkey platform authenticator across any website and browser.

---

## Key Features

- **Zero-Crate Architecture**: All cryptography, parsers, serializers, and networking are built from scratch in pure Rust standard library.
- **Hardware-Accelerated Cryptography**:
  - **Vault Encryption**: AES-256-GCM authenticated encryption with 96-bit random nonces and 128-bit authentication tags.
  - **Key Derivation**: PBKDF2-HMAC-SHA-512 with 100,000 iterations and 128-bit cryptographic salts.
  - **Passkey Algorithms**: Dual-engine supporting **ES256** (NIST ECDSA P-256 via Windows CNG `bcrypt.dll`) and **EdDSA** (Ed25519) per RFC 8152 / RFC 9053.
  - **TOTP Engine**: RFC 6238 / RFC 4226 supporting HMAC-SHA-1, HMAC-SHA-256, and HMAC-SHA-512 with custom time steps and digit lengths.
- **Zero-Daemon**: No background services or daemon processes left running in the background. CredShell only runs when you execute a command or launch the passkey listener.
- **Universal Passkey Support**: Intercepts passkey creation and sign-in attempts on all websites (Google, Apple, GitHub, Microsoft, Amazon, Twitter/X, Passkeys.io, WebAuthn.io, etc.) via the included browser extension.
- **Multi-Vault Isolation**: Manage separate encrypted vaults with their own master passwords (e.g. `credshell work.kbd ...` vs `credshell personal.kbd ...`).
- **Encrypted Cross-Device Sync**: Synchronize vaults across devices on local networks or air-gapped setups using ephemeral key exchange and AES-256-GCM encrypted binary blobs.
- **Atomic File Operations**: Prevents database corruption by staging saves in temporary files and committing atomically.

---

## Installation & Build

### Requirements
- Rust toolchain (stable 1.75+ or newer).

### Building from Source
```powershell
# Clone the repository and build with release optimizations
cargo build --release

# The compiled binary is located at:
.\target\release\credshell.exe
```

---

## Browser Extension (WebAuthn / Passkey Bridge)

To allow websites to use CredShell as your platform passkey authenticator:

1. Open your Chromium-based browser (Google Chrome, Microsoft Edge, Brave, Opera, Vivaldi).
2. Navigate to `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode** using the toggle switch in the top-right corner.
4. Click **Load unpacked** and select the `extension` folder inside this repository (`c:\Users\Admin\Documents\credshell\extension`).
5. The **CredShell Passkey Authenticator** extension is now installed.

### How It Works Under the Hood
- The extension runs a **two-tier architecture**:
  - `page_hook.js` executes in the page's execution context (`world: "MAIN"`) at `document_start`, hooking `navigator.credentials.create` and `navigator.credentials.get`. It reports to the browser that a platform passkey authenticator is available (`PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true`).
  - `background.js` (Manifest V3 Service Worker) communicates directly with the local CredShell endpoint (`http://127.0.0.1:5209`). Because requests originate from the extension service worker context, they are **completely immune to Mixed-Content blocks, Content-Security-Policy (CSP), and Private Network Access (PNA) restrictions**.

---

## Scripting & Automation Architecture

### Secure Password Handling
To protect master passwords from leakage via process listings (`ps`, `Get-Process`) and shell histories (`.bash_history`, PowerShell PSReadLine):
- The insecure command-line flag `-p` / `--password` **has been permanently removed**.
- Vault operations obtain master authentication via:
  1. The environment variable: `CREDSHELL_PASSWORD` (or `CREDSHELL_PASSPHRASE`). When supplied via environment variable, a security warning is displayed on CLI stderr reminding users not to expose secrets in shared environments.
  2. Zero-echo interactive terminal prompt (`prompt_passphrase` via Windows `SetConsoleMode` or Unix `stty -echo`) when the environment variable is unset.

Example:
```powershell
# Via environment variable:
$env:CREDSHELL_PASSWORD = "MySecurePassword123!"
credshell totp list

# Or run interactively (zero-echo masked password entry):
credshell totp list
```

### Modern Confirmation Architecture (No Terminal Y/N Prompts)
Interactive terminal `[y/N]` prompts have been eliminated in favor of contextual, native interfaces:
- **Web Applications**: Passkey registration and authentication confirmations are displayed inside the browser extension modal.
- **Desktop Applications & Synchronization**: Vault synchronization and desktop passkey authorizations trigger platform-native graphical dialogs (`MessageBoxW` on Windows, AppleScript on macOS, `zenity`/`kdialog` on Linux).
- **Android Mobile**: Delegated to the system Android Credential Manager sheet.
- **Automated Testing**: The passkey listener also supports `--auto-approve` for headless automated integration suites.

---

## CLI Usage Reference

All features in CredShell are driven by clean, scriptable subcommands.

```text
USAGE:
  credshell <command> [subcommand] [-v vault_path]
```

### Global Flags
| Flag | Description |
|---|---|
| `-v, --vault <path>` | Specify custom vault file path (default: `.credshell/vault.kdb`) |
| `-h, --help` | Display help and subcommand reference |

> **Tip:** You can specify `-v <path>` anywhere in the command:  
> `credshell totp list -v mydir/vault2.kbd`

---

### 1. Vault Management (`vault`)

#### Display Vault Status
Inspect vault version, device identifier, TOTP entries, and passkey counts:
```powershell
credshell vault status [-v <vault_path>]
```

#### Initialize a New Vault
Create and encrypt a new vault file:
```powershell
credshell vault create [-v <vault_path>]
# Example with custom vault path via -v:
credshell vault create -v mydir/work.kbd
```

#### Change Master Password
Re-encrypt the vault with a new master passphrase:
```powershell
credshell vault change-password [new_password]
```

---

### 2. Passkey / WebAuthn (`passkey`)

#### Start Active Platform Authenticator (Unified Login & Registration)
Starts the local WebAuthn listener on `127.0.0.1:5209` to service real-time browser and application passkey requests for **both registration and authentication**:
```powershell
# Standard mode (prompts via native GUI modal / browser extension):
credshell passkey [-v <vault_path>]

# With auto-approval (for headless automation / CI testing):
credshell passkey --auto-approve

# Custom port:
credshell passkey --port 5209
```

##### How Registration & Authentication Work:
- **Auto-Determined Unique ID (`<user>#<party>`)**: CredShell automatically determines passkey IDs in the standard format `"<username/email>#<party>"` (e.g. `alice#github.com`). No interactive terminal ID entry is needed.
- **Domain Matching (`*.example.com`)**: Stored relying parties maintain exact isolation (`example.com` vs `abc.example.com`), but during authentication, all passkeys matching `*.example.com` (exact domain, subdomains, parent domain, sibling subdomains) are presented for user selection.
- **Collision & Overwrite Handling**:
  - **Browser Extension & Desktop GUI**: If a registration attempt resolves to an existing ID (e.g. `userxyz#example.com`), CredShell prompts the user with an overwrite confirmation modal. Choosing Cancel aborts with `NotAllowedError`. Approving overwrites the key directly under the same ID without creating a backup.
  - **Android Credential Manager**: Because the system bottom sheet is managed by Android OS, existing keys with colliding IDs are automatically backed up by renaming the old key to `<id>-bak-<unix_timestamp>` and storing the newly registered key under the original `<id>`.
- **7-Day Backup Pruning**: While decrypting and reading the vault at startup, any backup passkey older than 7 days (`> 604,800` seconds) is permanently deleted from the vault.
- **Universal Relying Party Compatibility**: Full W3C WebAuthn Level 3 compliance with RFC 4648 URL-safe Base64 encoding, standard unpadded CBOR `fmt: "none"` attestation (AAGUID `00000000-0000-0000-0000-000000000000`), platform attachment, and internal transport definitions to ensure strict services (Google, WhatsApp, GitHub, Amazon) accept registrations seamlessly without MDS rejection.

#### List Active Passkeys
View all active registered passkeys in the vault (backup keys are excluded):
```powershell
credshell passkey list [-v <vault_path>]
```
*Output:*
```text
CredShell Vault "vault.kdb" (2 Active Passkeys):

• ID: alice#github.com            RP: github.com           User: alice            Alg: ES256 (P-256)    Signs: 3
• ID: bob#abc.example.com         RP: abc.example.com      User: bob              Alg: ES256 (P-256)    Signs: 1
```

#### List Backup Passkeys (`list-bak`)
View all backup passkeys created by Android collision replacements:
```powershell
credshell passkey list-bak [-v <vault_path>]
```
*Output:*
```text
CredShell Vault "vault.kdb" (1 Backup Passkeys):

• Restore ID: userxyz#example.com-bak        (Stored: userxyz#example.com-bak-1757059200) | Unix Time: 1757059200 | Signs: 2
```

#### Restore Backup Passkey (`restore <id-bak>`)
Restore a backup key to active status using the `<id>-bak` format (the current active key is moved to backup format `<id>-bak-<unix_timestamp>`):
```powershell
credshell passkey restore <id-bak> [-v <vault_path>]

# Example:
credshell passkey restore userxyz#example.com-bak
```

#### Delete a Passkey
Remove a passkey by its unique ID:
```powershell
credshell passkey delete <id_or_rp> [-v <vault_path>]
```

#### Install Native Messaging Manifest
Install the native messaging host definition for Chrome/Edge:
```powershell
credshell passkey install-manifest
```

---

### 3. TOTP Two-Factor Authenticator (`totp`)

#### Add New TOTP Account (Base32 or `otpauth://` URI)
Store a new TOTP secret in the vault using either an `otpauth://` URI (from QR codes) or raw Base32 secret:
```powershell
# Using an otpauth:// URI:
credshell totp add "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub" [-v <vault_path>]

# Using an otpauth:// URI with a custom ID:
credshell totp add github-work "otpauth://totp/GitHub:alice.work@company.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"

# Using raw Base32 secret:
credshell totp add google-personal JBSWY3DPEHPK3PXP --issuer Google --account alice@gmail.com
```
> If no ID is supplied on the command line, CredShell interactively prompts you to confirm or enter a unique ID (defaulting to the parsed URI label or issuer). Collisions are automatically detected and blocked.

#### Generate TOTP Code by ID
Generate current 6-digit TOTP code using the credential's unique ID:
```powershell
credshell totp get <id> [-v <vault_path>]

# Output formatted as JSON:
credshell totp get <id> --json [-v <vault_path>]
```
*Output:*
```text
Google

Current : 842 195
Next    : 309 481
Expires : 18s
Period  : 30s
```

#### List Stored TOTP Accounts
List all entries with their unique IDs:
```powershell
credshell totp list [-v <vault_path>]
```
*Output:*
```text
CredShell Vault "vault.kdb" (2 TOTP items):

• ID: google-personal      Issuer: Google           Account: alice@gmail.com
• ID: github-work          Issuer: GitHub           Account: alice.work@company.com
```

#### Delete a TOTP Account by ID
```powershell
credshell totp delete <id> [-v <vault_path>]
```

---

### 4. Cross-Device Vault Synchronization (`sync`)

Synchronize vaults between devices over local networks without exposing secrets to any third-party cloud servers.

#### Start Receiver (Device A)
Put Device A into receiver mode:
```powershell
credshell sync rx [--port 7443]
```

#### Transmit Vault (Device B)
Stream transactional updates from Device B to Device A:
```powershell
credshell sync tx <device_a_ip[:port]>
```

#### Export Encrypted Backup Blob
Export an encrypted binary backup (`.kxb`) containing vault delta entries:
```powershell
credshell sync export [backup_path.kxb]
```

#### Import Backup Blob
Transactionally import and merge an encrypted backup blob:
```powershell
credshell sync import <backup_path.kxb>
```

---

## Cryptographic Specifications

| Component | Standard / Algorithm | Details |
|---|---|---|
| **Vault Cipher** | AES-256-GCM | 256-bit keys, 96-bit CSPRNG nonces, 128-bit Poly1305/GHASH tag |
| **KDF** | PBKDF2-HMAC-SHA-512 | 100,000 iterations, 128-bit salt |
| **Passkey (ES256)** | ECDSA over NIST P-256 / SHA-256 | Constant-time Pure Rust NIST P-256 Jacobian arithmetic engine (Android, Linux, macOS, iOS, WASM) & Windows CNG (Windows), RFC 8152 COSE |
| **Passkey (EdDSA)** | Ed25519 (Edwards-curve Digital Signature) | Pure Rust RFC 8032 implementation with Edwards curve arithmetic |
| **KXSP Sync Protocol** | Ephemeral X25519 DH + Ed25519 | RFC 7748 Montgomery ladder key exchange with mutual Ed25519 authentication and Perfect Forward Secrecy |
| **TOTP Engine** | RFC 6238 / RFC 4226 | Constant-time HMAC-SHA1, HMAC-SHA256, HMAC-SHA512 |
| **WebAuthn Flags** | WebAuthn Level 3 | `UP` (User Present), `UV` (User Verified), `BE` (Backup Eligible), `BS` (Backup State) |

---

## Android & Termux Usage (Native App Passkeys: WhatsApp, Google, etc.)

CredShell compiles natively and runs directly on Android inside **Termux** (`aarch64-linux-android`).

### How Android Native App Passkeys Work (vs. Desktop)

- **On Desktop**: Web browsers (Chrome, Edge, Firefox) permit extension hooks into `navigator.credentials`, sending requests directly to `http://127.0.0.1:5209`.
- **On Android**: Native apps (like **WhatsApp**, Google, Amazon, GitHub app) do **not** run inside a web browser and do not use browser extensions. Instead, Android OS routes all passkey requests through the OS-level **Credential Manager API** (`android.credentials.CredentialManager`).
- Android OS only dispatches passkey requests to apps registered in the OS manifest as a system `CredentialProviderService` (this is how Proton Pass, Bitwarden, and 1Password work on Android).
- **Pure Socket Communication (No Termux Dependency)**: The CredShell companion app is a pure, independent HTTP client that communicates directly with the hosted CredShell daemon socket (`http://127.0.0.1:5209`, configurable in app settings). It does **not** rely on or inspect Termux.
- **Native WebAuthn Origin Fidelity**: Native Android apps require the origin to be the SHA-256 fingerprint of their signing certificate (`android:apk-key-hash:<hash>`) along with `androidPackageName`. CredShell dynamically calculates this from the calling application's signature history so relying parties (like WhatsApp) verify and accept the passkey without rejection.
- **The Solution**: CredShell includes an ultra-lightweight Android Credential Provider Bridge APK (`android/`):
  1. The bridge registers in Android Settings as your phone's system Credential Provider (named **"CredShell"**).
  2. When WhatsApp or any app requests a passkey, Android OS passes the WebAuthn request to the CredShell bridge.
  3. The bridge forwards the request with full origin and package metadata to the hosted socket (`http://127.0.0.1:5209`).
  4. Your local Rust **CredShell** handles the vault, cryptographic signatures, and auto-approval/terminal interaction in pure Rust, then returns the signed assertion to WhatsApp.
  5. **Completely Local & Private**: Everything runs locally on your device without third-party cloud intermediaries.

---

### Step-by-Step Android Setup

#### Step 1: Install & Build CredShell
Run the CredShell daemon on your device (e.g. inside Termux, Linux chroot, or any terminal environment):
```bash
# 1. Install Rust and Git
pkg update
pkg install rust git

# 2. Clone and build CredShell
git clone <repo-url> ~/credshell
cd ~/credshell
cargo build --release

# 3. Verify native build
./target/release/credshell --help
```

#### Step 2: Install the CredShell Android Credential Provider Bridge
The lightweight open-source bridge APK is located in `android/`:
- **Pre-built APK**: Install `android/app/build/outputs/apk/debug/app-debug.apk`:
  ```bash
  adb install -r android/app/build/outputs/apk/debug/app-debug.apk
  ```
- **Configure Socket**: Open the **CredShell** app on your phone to configure or test the hosted socket endpoint (default: `http://127.0.0.1:5209`).

#### Step 3: Enable CredShell in Android Settings
1. On your phone, open **Settings** → **Passwords, passkeys & accounts** (or search **"Credential Manager"** / **"Autofill service"**).
2. Under **Preferred service** (or **Additional providers**), tap **CredShell**.
3. Tap **OK** to confirm CredShell as your system credential provider.

#### Step 4: Start Daemon & Authenticate in WhatsApp
1. In your terminal, start the passkey listener:
   ```bash
   cd ~/credshell
   ./target/release/credshell passkey
   ```
2. Open **WhatsApp** → **Settings** → **Account** → **Passkeys** → **Create a passkey**.
3. Android OS displays the CredShell passkey prompt.
4. CredShell creates the NIST P-256 passkey, saves it to your encrypted vault, and returns the attestation.
5. WhatsApp confirms: **"Passkey created successfully!"**

---

## Security Guarantees

1. **Zero Memory Leaks**: Sensitive cryptographic buffers and passphrases are zeroized after execution using volatile memory writes and compiler fences.
2. **Zero Third-Party Telemetry / Network Calls**: The binary does not make outbound network requests. Passkey listening binds strictly to loopback (`127.0.0.1`).
3. **No Attack Surface from Daemons**: No background daemon is installed. The software runs only when invoked.
4. **Zero-Crate Supply Chain Security**: With zero dependencies in `Cargo.toml`, CredShell is completely immune to third-party crate vulnerabilities, typosquatting attacks, and malicious dependency updates.
