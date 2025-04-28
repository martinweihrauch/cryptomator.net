# Cryptomator.Net Library Overview

## 1. What is Cryptomator?

Cryptomator is a system designed for client-side encryption, primarily aimed at securing files stored in cloud services, but equally effective for local storage. It operates by creating encrypted "vaults". To the user, a vault appears as a regular drive or folder where they can store files and directories normally. However, the actual files stored within the vault (e.g., on Dropbox, Google Drive, or a local disk) are individually encrypted, including their names and the directory structure itself.

Cryptomator.Net is a C# implementation of the core cryptographic logic defined by the Cryptomator project, specifically adhering to the Universal Vault Format (UVF) version 3. It provides the necessary tools to interact with Cryptomator vaults programmatically within .NET applications.

**Disclaimer:** As noted in the main README, this C# library was semi-automatically translated from the official Java implementation. While efforts were made for accuracy, it may contain cryptographic flaws or subtle errors. It is intended for educational/experimental use and should **not** be used for securing sensitive production data without a thorough independent security audit.

## 2. Purpose: Creating Secure Vaults

The primary purpose of Cryptomator (and thus Cryptomator.Net) is to create and manage these secure vaults. A vault is essentially a designated folder on your storage medium (local or cloud) with two key characteristics:

1.  **Encrypted Content:** All file contents stored within the vault's underlying folder structure are encrypted.
2.  **Encrypted Structure:** The names of files and directories are also encrypted, and the directory hierarchy is obfuscated. This means someone accessing the raw vault folder cannot determine the original filenames, directory names, or even the original folder structure just by looking at the stored data.

This approach ensures that even if the storage provider (or anyone accessing the physical storage) is compromised, the actual data remains confidential and unintelligible without the user's password.

## 3. How Encryption Works

Cryptomator employs a multi-layered encryption strategy:

*   **File Content Encryption:** The actual data within each file is encrypted using strong symmetric encryption.
*   **Filename Encryption:** The names of files and directories are encrypted using a different authenticated encryption scheme.
*   **Directory Structure Obfuscation:** Instead of storing encrypted directory names directly, Cryptomator uses a hashing mechanism based on unique Directory IDs to create the physical paths where encrypted files are stored.

### 3.1 File Content Encryption

-   Each file has a **File Header** stored alongside its encrypted content (or sometimes embedded within the first part of the encrypted file stream).
-   This header contains metadata necessary for decryption, primarily a unique **Nonce** (96 bits) and an encrypted **Content Key** (256 bits, AES).
-   The Content Key itself is encrypted using AES-GCM, with the encryption key derived from the vault's master key and authenticated using the header's Nonce and Seed ID.
-   The actual file content is encrypted in chunks using **AES-GCM** (Galois/Counter Mode). AES-GCM provides both confidentiality (encryption) and integrity/authenticity (protection against tampering).
-   Each chunk uses its own unique nonce and includes the chunk number and the header's nonce as Additional Authenticated Data (AAD). This prevents chunks from being maliciously reordered or moved between files.

### 3.2 Filename Encryption

-   Filename encryption uses **AES-SIV** (Synthetic Initialization Vector). AES-SIV is an authenticated encryption mode particularly suited for encrypting small, deterministic pieces of data like filenames, where the same input should always produce the same output (unlike AES-GCM which uses random nonces for content).
-   The encryption process uses a specific **Filename Encryption Key** (derived from the master key).
-   Crucially, the **Directory ID** of the directory containing the file is used as Additional Authenticated Data (AAD) during filename encryption/decryption. This means:
    -   Encrypting the same filename ("report.txt") in two different directories will result in two different encrypted filenames.
    -   Moving an encrypted file between directories without re-encrypting the name will cause decryption to fail (as the Directory ID used for decryption won't match).
-   The resulting encrypted byte sequence is then encoded using **Base64Url** to make it filesystem-safe. For files, the `.uvf` extension is typically appended.

### 3.3 Directory Structure Obfuscation

-   Cryptomator does *not* simply encrypt directory names and store them. Instead, it obfuscates the structure.
-   Each directory within the vault is assigned a unique **Directory ID**.
-   When a directory is created, its Directory ID is used to calculate a **Hashed Path**. This hash (derived using HMAC-SHA256 with a specific key derived from the master key, then truncated and Base32 encoded) determines the physical subdirectory within the vault's `d` folder where the directory's contents (encrypted files and `dir.uvf` files for subdirectories) will be stored.
-   Inside this hashed path directory, a special file named `dir.uvf` is created. This file contains the **encrypted Directory Metadata**, including the directory's unique ID. This metadata is encrypted similarly to file headers.

This means the physical path structure inside the vault (`d/XX/YYYYYYYY/...`) bears no direct resemblance to the user's logical directory structure.

## 4. Key Management

Cryptomator's security relies on robust key management derived from a single user password:

1.  **Password:** The user provides a strong password for the vault.
2.  **Scrypt:** The password, along with a unique salt stored in the `masterkey.cryptomator` file, is fed into the **scrypt** key derivation function. Scrypt is computationally expensive, making brute-force attacks on the password very difficult. This produces the raw **Vault Master Key** (typically 256 bits).
3.  **Master Key:** This single raw key is the root of trust for the entire vault.
4.  **Key Derivation (HKDF):** The raw Master Key is *never* used directly for encryption. Instead, specific **sub-keys** are derived from it using **HKDF** (HMAC-based Key Derivation Function based on SHA-256). HKDF takes the master key, an optional salt (often not used for sub-keys), and a context-specific "info" parameter (like "fileHeader", "fileContent", "siv", "hmac", "directoryId") to deterministically generate different keys for different purposes:
    *   **Header Encryption Key:** Used to encrypt/decrypt the Content Key within file headers.
    *   **Content Encryption Key:** Stored encrypted in the header, decrypted using the Header Key, and then used for AES-GCM file content encryption. (Note: The *actual* content key is unique per file and generated randomly, then encrypted *with* the derived header key).
    *   **Filename Encryption Key (SIV Key):** Used for AES-SIV filename encryption.
    *   **Filename/Directory ID Hashing Key (HMAC Key):** Used with HMAC-SHA256 to hash Directory IDs for path generation.
5.  **Key Erasure:** The library aims to keep raw key material in memory for the shortest time possible and uses methods like `CryptographicOperations.ZeroMemory` to overwrite sensitive key data when it's no longer needed (e.g., via `Destroy()` methods).

This hierarchical derivation ensures that even if one sub-key were somehow compromised (highly unlikely without the master key), it wouldn't compromise the other keys or the master key itself.

## 5. Cryptographic Algorithms Used

*   **Password Hashing:** scrypt
*   **Key Derivation:** HKDF (HMAC-based KDF) with SHA-256
*   **File Content Encryption:** AES-256-GCM
*   **File Header (Content Key) Encryption:** AES-256-GCM
*   **Filename Encryption:** AES-256-SIV
*   **Directory ID Hashing:** HMAC-SHA256 (Truncated)

## 6. Vault Structure

A typical Cryptomator vault folder contains:

1.  **`masterkey.cryptomator` file:** An encrypted JSON file containing the salt and parameters needed for scrypt, along with the master key encrypted using scrypt and the user's password.
2.  **`d` directory:** The root directory for all encrypted data.
3.  **Inside `d`:** A nested structure of directories whose names are derived from the **hashed Directory IDs**. The depth and specific names depend on the hash output. For example: `d/AB/CDEFGHIJKLMNOPQRSTUVWXYZ234567/`.
4.  **Inside Hashed Path Directories:**
    *   **Encrypted Files:** Files with Base64Url-encoded encrypted names, usually ending in `.uvf`. Example: `FX_ZQ3...A.uvf`.
    *   **`dir.uvf` files:** Placeholder files representing subdirectories. Each `dir.uvf` contains the encrypted metadata (including the unique Directory ID) of the subdirectory it represents. The *actual* content of that subdirectory resides in *its own* hashed path elsewhere within the `d` structure.

### ASCII Diagram Example

Imagine a user creates a vault with the following structure:

```
MyVault/
├── Documents/
│   ├── report.docx
│   └── notes.txt
└── Photos/
    └── vacation.jpg
```

The actual encrypted vault folder might look something like this (simplified hash paths):

```
(Storage Location)/EncryptedVaultFolder/
├── masterkey.cryptomator
└── d/
    ├── 3K/  <-- Hashed path for root ("/") directory ID
    │   ├── dir.uvf                  <-- Represents 'Documents' subdir
    │   └── dir.uvf                  <-- Represents 'Photos' subdir
    │
    ├── FQ/  <-- Hashed path for 'Documents' directory ID
    │   ├── ABCDEFGHIJ...KL.uvf      <-- Encrypted 'report.docx'
    │   └── ZYXWVUTSRQ...PO.uvf      <-- Encrypted 'notes.txt'
    │
    └── M7/  <-- Hashed path for 'Photos' directory ID
        └── 1234567890...AB.uvf      <-- Encrypted 'vacation.jpg'

```

**Note:** The `dir.uvf` files in `d/3K/` don't *contain* the encrypted files of their respective subdirectories. They only contain the encrypted *metadata* (like the Directory ID) for `Documents` and `Photos`. The actual encrypted files (`ABC...KL.uvf`, `ZYX...PO.uvf`, `123...AB.uvf`) are located within the directories corresponding to the *hashed IDs* of `Documents` (`d/FQ/`) and `Photos` (`d/M7/`).

This structure effectively hides the original layout and naming from anyone browsing the encrypted vault folder directly. 