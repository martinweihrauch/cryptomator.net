# Cryptomator.Net Library Documentation

## Overview

Cryptomator.Net is a C# implementation of the Cryptomator library, providing secure client-side encryption for cloud storage. The library follows the Universal Vault Format (UVF) specification and provides APIs for file name encryption, file content encryption, and key management.

<span style="color:red">!! WARNING !!</span>

Disclaimer
The provided C# code was semi-automatically translated from the original Java implementation and may contain serious cryptographic flaws or errors.
This project is distributed under the MIT License and is intended for educational and experimental purposes only.
It is strongly advised not to use this C# implementation in production environments or for securing sensitive information without conducting a thorough and independent review.

Under no circumstances shall the authors or contributors be held liable for any damages, losses (including but not limited to financial, data, health, or other types of harm) resulting from the use of this software.

## Getting Started

### Installation

Add the CryptomatorLib project to your solution or reference the compiled DLL:

```csharp
<PackageReference Include="CryptomatorLib" Version="1.0.0" />
```

### Basic Usage

Here's a simple example of how to use the library:

```csharp
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using System;
using System.IO;
using System.Security.Cryptography;

// Create or load a masterkey
byte[] rawMasterkey = new byte[32]; // For demo - use secure random generation
using (var rng = RandomNumberGenerator.Create())
{
    rng.GetBytes(rawMasterkey);
}

// Create a UVF masterkey from raw key
UVFMasterkey masterkey = UVFMasterkey.CreateFromRaw(rawMasterkey);

// Get a cryptor for file operations
CryptoFactory factory = CryptoFactory.GetFactory();
Cryptor cryptor = factory.Create(masterkey);

// Encrypt and decrypt file names
string directoryId = Guid.NewGuid().ToString(); // Each directory has a unique ID
string originalFileName = "document.txt";
string encryptedFileName = cryptor.FileNameCryptor().EncryptFilename(originalFileName, directoryId);
string decryptedFileName = cryptor.FileNameCryptor().DecryptFilename(encryptedFileName, directoryId);

// Encrypt file content
byte[] fileContent = File.ReadAllBytes("document.txt");
byte[] encryptedContent = cryptor.FileContentCryptor().Encrypt(fileContent);

// Decrypt file content
byte[] decryptedContent = cryptor.FileContentCryptor().Decrypt(encryptedContent);

// Clean up sensitive data
((DestroyableMasterkey)masterkey).Destroy();
```

## Architecture

The library is organized into three main components:

1. **API** - Interfaces that define the contract for the library
2. **Common** - Utility classes and implementations shared across versions
3. **V3** - Implementation of the Universal Vault Format (version 3)

### Key Components

#### Masterkey Management

1. **Masterkey** - Base interface for encryption keys
2. **UVFMasterkey** - Interface for the Universal Vault Format masterkey
3. **DestroyableMasterkey** - Interface for keys that can be securely destroyed
4. **RevolvingMasterkey** - Interface for keys that support rotation (multiple revisions)

```csharp
// Create a new masterkey from a passphrase
MasterkeyFile file = MasterkeyFileAccess.CreateFromPassphrase("your-secure-passphrase");

// Save to disk
MasterkeyFileAccess.Save(file, "masterkey.cryptomator");

// Load from disk with passphrase
MasterkeyFile loadedFile = MasterkeyFileAccess.Load("masterkey.cryptomator");
byte[] rawKey = MasterkeyFileAccess.LoadRawMasterkey(loadedFile, "your-secure-passphrase");

// Create UVF masterkey and use it
UVFMasterkey masterkey = UVFMasterkey.CreateFromRaw(rawKey);

// Securely destroy the key when finished
if (masterkey is DestroyableMasterkey destroyable)
{
    destroyable.Destroy();
}
```

#### Cryptographic Operations

1. **CryptoFactory** - Creates cryptors for specific vault versions
2. **Cryptor** - Main entry point for cryptographic operations
3. **FileNameCryptor** - Handles encryption/decryption of filenames
4. **FileContentCryptor** - Handles encryption/decryption of file contents
5. **FileHeaderCryptor** - Manages file headers containing metadata

```csharp
// Create cryptor from masterkey
CryptoFactory factory = CryptoFactory.GetFactory();
Cryptor cryptor = factory.Create(masterkey);

// File name encryption
string encryptedName = cryptor.FileNameCryptor().EncryptFilename("document.txt", directoryId);

// File content encryption/decryption
FileHeader header = cryptor.FileHeaderCryptor().Create();
byte[] headerBytes = cryptor.FileHeaderCryptor().HeaderBytes(header);

// Write file with header followed by encrypted content
using (var outputStream = File.Create("encrypted.bin"))
{
    outputStream.Write(headerBytes, 0, headerBytes.Length);
    
    // Encrypt content
    byte[] encryptedContent = cryptor.FileContentCryptor().EncryptWithoutHeader(content, header);
    outputStream.Write(encryptedContent, 0, encryptedContent.Length);
}
```

## Working with Files

### File Name Encryption

Each directory in a Cryptomator vault has a unique ID. This ID is used as additional authenticated data during filename encryption to ensure that moving a file to a different directory changes its encrypted name.

```csharp
// Generate a unique ID for each directory
string directoryId = Guid.NewGuid().ToString();

// Encrypt a file name
string encryptedName = cryptor.FileNameCryptor().EncryptFilename("document.txt", directoryId);

// Decrypt a file name
string decryptedName = cryptor.FileNameCryptor().DecryptFilename(encryptedName, directoryId);
```

### File Content Encryption

File content encryption involves two steps:
1. Creating a file header with encryption parameters
2. Encrypting the content using those parameters

```csharp
// Create file header
FileHeader header = cryptor.FileHeaderCryptor().Create();

// Encrypt content with header
byte[] encryptedContent = cryptor.FileContentCryptor().Encrypt(content, header);

// Or for more control:
byte[] headerBytes = cryptor.FileHeaderCryptor().HeaderBytes(header);
byte[] encryptedWithoutHeader = cryptor.FileContentCryptor().EncryptWithoutHeader(content, header);

// Decrypt content
FileHeader decryptedHeader = cryptor.FileHeaderCryptor().DecryptHeader(headerBytes);
byte[] decryptedContent = cryptor.FileContentCryptor().DecryptWithoutHeader(encryptedWithoutHeader, decryptedHeader);
```

## Key Derivation and Security

The library uses HKDF (HMAC-based Key Derivation Function) for deriving keys from the master key, and scrypt for passphrase-based key derivation:

```csharp
// HKDF example (internal library use)
byte[] derivedKey = HKDFHelper.DeriveKey(
    masterKey,     // Input key material
    salt,          // Optional salt
    contextInfo,   // Context information
    outputLength   // Length of output key
);

// Secure passphrase handling (when loading masterkey files)
byte[] rawKey = MasterkeyFileAccess.LoadRawMasterkey(masterkeyFile, passphrase);
try {
    // Use the key
    UVFMasterkey masterkey = UVFMasterkey.CreateFromRaw(rawKey);
    // ...operations...
}
finally {
    // Securely erase from memory
    CryptographicOperations.ZeroMemory(rawKey);
}
```

## Best Practices

1. **Always destroy keys when finished**: Use the `Destroy()` method on `DestroyableMasterkey` implementations to securely erase sensitive data.

2. **Use strong passphrases**: When creating masterkey files, use strong, random passphrases.

3. **Handle encrypted data securely**: Keep encrypted data and key material separate, and never store keys unencrypted.

4. **Use directory IDs consistently**: For each directory, generate a unique ID and use it consistently for all files in that directory.

5. **Error handling**: Catch specific exceptions like `InvalidPassphraseException`, `AuthenticationFailedException`, and `CryptoException` to handle different error scenarios gracefully.

## Conclusion

The Cryptomator.Net library provides powerful, standards-based encryption for files, compatible with the Cryptomator ecosystem. By following this documentation, you can integrate secure, client-side encryption into your .NET applications.
