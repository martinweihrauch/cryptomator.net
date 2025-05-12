/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others 
 * Copyright (c) 2025 Smart In Venture GmbH for C# Porting
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *     
 *     Smart In Venture GmbH - C# Porting (c) 2025
 *     
 *******************************************************************************/

// Copyright (c) Smart In Venture GmbH 2025 of the C# Porting

using System.Security.Cryptography;
using UvfLib.Api;
using UvfLib.Common;
using UvfLib.VaultHelpers; // Added for VaultKeyHelper

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("UvfLib.Tests")]

namespace UvfLib
{
    /// <summary>
    /// Represents an unlocked Uvf vault and provides high-level access
    /// to its cryptographic operations.
    /// </summary>
    public sealed class Vault // Consider adding IDisposable if Cryptor needs disposal
    {
        private readonly Cryptor _cryptor;
        private readonly PerpetualMasterkey _masterkey; // Store the masterkey if needed for operations like ChangePassword
        private static readonly RandomNumberGenerator CsPrng = RandomNumberGenerator.Create(); // Static instance for loading

        /// <summary>
        /// Initializes a new instance of the <see cref="Vault"/> class.
        /// Private constructor to force usage of static factory methods like Load.
        /// </summary>
        /// <param name="cryptor">The initialized cryptor for this vault.</param>
        /// <param name="masterkey">The underlying masterkey.</param>
        private Vault(Cryptor cryptor, PerpetualMasterkey masterkey)
        {
            _cryptor = cryptor ?? throw new ArgumentNullException(nameof(cryptor));
            _masterkey = masterkey ?? throw new ArgumentNullException(nameof(masterkey));
        }

        // Static utility for key file creation (doesn't require a Vault instance)
        /// <summary>
        /// Creates the encrypted master key file content for a new vault.
        /// </summary>
        /// <param name="password">The password for the new vault.</param>
        /// <param name="pepper">Optional pepper to use during key derivation. If null, an empty pepper is used.</param>
        /// <returns>A byte array containing the encrypted master key file data.</returns>
        /// <exception cref="ArgumentNullException">If password is null.</exception>
        /// <exception cref="CryptoException">If key generation or encryption fails.</exception>
        public static byte[] CreateNewVaultKeyFileContent(string password, byte[]? pepper = null)
        {
            // Delegate to VaultKeyHelper
            return VaultKeyHelper.CreateNewVaultKeyFileContentInternal(password, pepper);
        }


        /// <summary>
        /// Loads a vault's Cryptor instance using the master key file content and password.
        /// This Cryptor instance is needed for all subsequent file/directory operations.
        /// </summary>
        /// <param name="encryptedKeyFileContent">The byte content of the master key file.</param>
        /// <param name="password">The vault password.</param>
        /// <param name="pepper">Optional pepper to use during key derivation. If null, an empty pepper is used.</param>
        /// <returns>An initialized Vault instance ready for operations.</returns>
        /// <exception cref="ArgumentNullException">If key content or password is null.</exception>
        /// <exception cref="InvalidPassphraseException">If the password is incorrect.</exception>
        /// <exception cref="AuthenticationFailedException">If the master key file MAC is invalid.</exception>
        /// <exception cref="UnsupportedVaultFormatException">If the vault format is not supported.</exception>
        /// <exception cref="MasterkeyLoadingFailedException">For other key loading errors.</exception>
        /// <exception cref="CryptoException">For general cryptographic errors.</exception>
        public static Vault Load(byte[] encryptedKeyFileContent, string password, byte[]? pepper = null)
        {
            if (encryptedKeyFileContent == null) throw new ArgumentNullException(nameof(encryptedKeyFileContent));
            if (password == null) throw new ArgumentNullException(nameof(password)); // Check password early
            byte[] effectivePepper = pepper ?? Array.Empty<byte>(); // Use provided pepper or default empty

            // 1. Parse the masterkey file content
            MasterkeyFile masterkeyFile = MasterkeyFile.FromJson(encryptedKeyFileContent);

            // 2. Unlock the masterkey using the password and pepper
            var keyAccessor = new MasterkeyFileAccess(effectivePepper, CsPrng);
            PerpetualMasterkey masterkey = keyAccessor.Unlock(masterkeyFile, password);

            // 3. Get the appropriate CryptorProvider based on the master key format
            CryptorProvider.Scheme scheme;
            // Check VaultVersion first, assuming 8+ uses UVF format
            // TODO: Refine this logic if older non-UVF schemes are supported by PerpetualMasterkey
            if (masterkeyFile.VaultVersion >= 8)
            {
                scheme = CryptorProvider.Scheme.UVF_DRAFT;
            }
            else
            {
                // Attempt to map older schemes based on properties if possible
                // Example (needs verification based on actual V6/V7 masterkey files):
                // if (masterkeyFile.ContentEncryptionScheme == "AES-GCM" && ...) scheme = CryptorProvider.Scheme.SIV_GCM;
                // else if (...) scheme = CryptorProvider.Scheme.SIV_CTRMAC;
                // else ...

                // Use the correct constructor for the exception
                var dummyUri = new Uri("file://masterkey.cryptomator"); // Placeholder URI
                var detectedFormat = VaultFormat.Unknown; // Or try to map version
                string errorMessage = $"Unsupported vault version ({masterkeyFile.VaultVersion}) or unable to determine scheme.";
                throw new UnsupportedVaultFormatException(dummyUri, detectedFormat, errorMessage);
            }

            CryptorProvider provider = CryptorProvider.ForScheme(scheme);

            // 4. Get the specific Cryptor implementation using the provider and masterkey
            Cryptor cryptor = provider.Provide(masterkey, CsPrng);

            // 5. Return a new Vault instance containing the cryptor and masterkey
            return new Vault(cryptor, masterkey);
        }

        // Static utility for changing password (doesn't require a Vault instance)
        /// <summary>
        /// Changes the password for an existing vault's master key file content.
        /// </summary>
        /// <param name="encryptedKeyFileContent">The current byte content of the master key file.</param>
        /// <param name="oldPassword">The current vault password.</param>
        /// <param name="newPassword">The desired new vault password.</param>
        /// <param name="pepper">Optional pepper to use during key derivation. If null, an empty pepper is used.</param>
        /// <returns>A byte array containing the newly encrypted master key file data.</returns>
        /// <exception cref="ArgumentNullException">If key content or passwords are null.</exception>
        /// <exception cref="InvalidPassphraseException">If the oldPassword is incorrect.</exception>
        // ... other exceptions from Load and Save ...
        public static byte[] ChangeVaultPassword(byte[] encryptedKeyFileContent, string oldPassword, string newPassword, byte[]? pepper = null)
        {
            // Delegate to VaultKeyHelper
            return VaultKeyHelper.ChangeVaultPasswordInternal(encryptedKeyFileContent, oldPassword, newPassword, pepper);
        }


        // --- Instance Methods for Operations ---

        /// <summary>
        /// Encrypts a filename for storage within the vault's root directory.
        /// </summary>
        /// <param name="plaintextFilename">The original filename.</param>
        /// <returns>The encrypted filename (Base64URL encoded + .uvf extension).</returns>
        /// <exception cref="ArgumentNullException">If plaintextFilename is null.</exception>
        /// <exception cref="InvalidOperationException">If the vault is not initialized correctly.</exception>
        /// <exception cref="CryptoException">If encryption fails.</exception>
        public string EncryptFilenameForRoot(string plaintextFilename)
        {
            if (plaintextFilename == null) throw new ArgumentNullException(nameof(plaintextFilename));
            var dirCryptor = _cryptor.DirectoryContentCryptor();
            if (dirCryptor == null) throw new InvalidOperationException("Directory cryptor not available.");

            DirectoryMetadata rootMetadata = dirCryptor.RootDirectoryMetadata();
            IDirectoryContentCryptor.Encrypting nameEncryptor = dirCryptor.FileNameEncryptor(rootMetadata);
            return nameEncryptor.Encrypt(plaintextFilename);
        }

        /// <summary>
        /// Decrypts a filename from the vault's root directory.
        /// </summary>
        /// <param name="encryptedFilename">The encrypted filename (including .uvf extension).</param>
        /// <returns>The original plaintext filename.</returns>
        /// <exception cref="ArgumentNullException">If encryptedFilename is null.</exception>
        /// <exception cref="InvalidOperationException">If the vault is not initialized correctly.</exception>
        /// <exception cref="ArgumentException">If the encryptedFilename format is invalid.</exception>
        /// <exception cref="AuthenticationFailedException">If the filename authentication fails.</exception>
        /// <exception cref="CryptoException">If decryption fails.</exception>
        public string DecryptFilenameFromRoot(string encryptedFilename)
        {
            if (encryptedFilename == null) throw new ArgumentNullException(nameof(encryptedFilename));
            var dirCryptor = _cryptor.DirectoryContentCryptor();
            if (dirCryptor == null) throw new InvalidOperationException("Directory cryptor not available.");

            DirectoryMetadata rootMetadata = dirCryptor.RootDirectoryMetadata();
            IDirectoryContentCryptor.Decrypting nameDecryptor = dirCryptor.FileNameDecryptor(rootMetadata);
            return nameDecryptor.Decrypt(encryptedFilename);
        }

        /// <summary>
        /// Gets the encrypted directory path for the vault's root directory.
        /// </summary>
        /// <returns>The encrypted path (e.g., "d/XX/YYYY...").</returns>
        /// <exception cref="InvalidOperationException">If the vault is not initialized correctly.</exception>
        public string GetRootDirectoryPath()
        {
            var dirCryptor = _cryptor.DirectoryContentCryptor();
            if (dirCryptor == null) throw new InvalidOperationException("Directory cryptor not available.");

            DirectoryMetadata rootMetadata = dirCryptor.RootDirectoryMetadata();
            return dirCryptor.DirPath(rootMetadata);
        }

        /// <summary>
        /// Gets the DirectoryMetadata for the vault's root directory.
        /// </summary>
        /// <returns>The DirectoryMetadata for the root.</returns>
        /// <exception cref="InvalidOperationException">If the vault is not initialized correctly.</exception>
        public DirectoryMetadata GetRootDirectoryMetadata()
        {
            var dirCryptor = _cryptor.DirectoryContentCryptor();
            if (dirCryptor == null) throw new InvalidOperationException("Directory cryptor not available.");
            return dirCryptor.RootDirectoryMetadata();
        }

        /// <summary>
        /// Returns a Stream that encrypts data as it is written to the underlying output stream.
        /// Handles file header creation and chunk encryption automatically.
        /// </summary>
        /// <param name="outputStream">The stream to write the encrypted data (header + content) to.</param>
        /// <param name="leaveOpen">Whether to leave the underlying outputStream open when the encrypting stream is disposed.</param>
        /// <returns>A Stream wrapper that performs encryption.</returns>
        /// <exception cref="ArgumentNullException">If outputStream is null.</exception>
        /// <exception cref="ArgumentException">If outputStream is not writable.</exception>
        /// <exception cref="InvalidOperationException">If the vault is not initialized correctly.</exception>
        public Stream GetEncryptingStream(Stream outputStream, bool leaveOpen = false)
        {
            // Delegate to VaultStreamHelper
            return VaultStreamHelper.GetEncryptingStreamInternal(_cryptor, outputStream, leaveOpen);
        }

        /// <summary>
        /// Returns a Stream that decrypts data as it is read from the underlying input stream.
        /// Handles file header reading/decryption and chunk decryption automatically.
        /// </summary>
        /// <param name="inputStream">The stream to read the encrypted data (header + content) from.</param>
        /// <param name="leaveOpen">Whether to leave the underlying inputStream open when the decrypting stream is disposed.</param>
        /// <returns>A Stream wrapper that performs decryption.</returns>
        /// <exception cref="ArgumentNullException">If inputStream is null.</exception>
        /// <exception cref="ArgumentException">If inputStream is not readable.</exception>
        /// <exception cref="InvalidOperationException">If the vault is not initialized correctly.</exception>
        /// <exception cref="InvalidCiphertextException">If the header or content ciphertext is invalid/corrupt.</exception>
        /// <exception cref="AuthenticationFailedException">If header or content authentication fails.</exception>
        public Stream GetDecryptingStream(Stream inputStream, bool leaveOpen = false)
        {
            // Delegate to VaultStreamHelper
            return VaultStreamHelper.GetDecryptingStreamInternal(_cryptor, inputStream, leaveOpen);
        }

        // --- Directory Metadata Operations ---

        /// <summary>
        /// Creates a new DirectoryMetadata object containing a unique directory ID.
        /// This object is needed before encrypting its content for a dir.uvf file.
        /// </summary>
        /// <returns>A new DirectoryMetadata instance.</returns>
        /// <exception cref="InvalidOperationException">If the vault is not initialized correctly.</exception>
        public DirectoryMetadata CreateNewDirectoryMetadata()
        {
            return VaultDirectoryHelper.CreateNewDirectoryMetadataInternal(_cryptor);
        }

        /// <summary>
        /// Encrypts the given DirectoryMetadata.
        /// The result is the binary content to be written to a dir.uvf file.
        /// </summary>
        /// <param name="metadata">The directory metadata to encrypt.</param>
        /// <returns>The encrypted binary content for a dir.uvf file.</returns>
        /// <exception cref="ArgumentNullException">If metadata is null.</exception>
        /// <exception cref="InvalidOperationException">If the vault is not initialized correctly.</exception>
        /// <exception cref="CryptoException">If encryption fails.</exception>
        public byte[] EncryptDirectoryMetadata(DirectoryMetadata metadata)
        {
            return VaultDirectoryHelper.EncryptDirectoryMetadataInternal(_cryptor, metadata);
        }

        /// <summary>
        /// Decrypts the content of a dir.uvf file.
        /// </summary>
        /// <param name="encryptedMetadata">The encrypted binary content read from a dir.uvf file.</param>
        /// <returns>The decrypted DirectoryMetadata instance.</returns>
        /// <exception cref="ArgumentNullException">If encryptedMetadata is null.</exception>
        /// <exception cref="InvalidOperationException">If the vault is not initialized correctly.</exception>
        /// <exception cref="InvalidCiphertextException">If the ciphertext is invalid/corrupt.</exception> // May also throw ArgumentException for size
        /// <exception cref="AuthenticationFailedException">If metadata authentication fails.</exception>
        public DirectoryMetadata DecryptDirectoryMetadata(byte[] encryptedMetadata)
        {
            return VaultDirectoryHelper.DecryptDirectoryMetadataInternal(_cryptor, encryptedMetadata);
        }

        // --- Contextual Filename/Path Operations ---

        /// <summary>
        /// Encrypts a filename using the context of a specific directory.
        /// </summary>
        /// <param name="plaintextFilename">The original filename.</param>
        /// <param name="directoryMetadata">The DirectoryMetadata of the parent directory.</param>
        /// <returns>The encrypted filename (Base64URL encoded + .uvf extension).</returns>
        /// <exception cref="ArgumentNullException">If plaintextFilename or directoryMetadata is null.</exception>
        /// <exception cref="InvalidOperationException">If the vault is not initialized correctly.</exception>
        /// <exception cref="CryptoException">If encryption fails.</exception>
        public string EncryptFilename(string plaintextFilename, DirectoryMetadata directoryMetadata)
        {
            return VaultDirectoryHelper.EncryptFilenameInternal(_cryptor, directoryMetadata, plaintextFilename);
        }

        /// <summary>
        /// Decrypts a filename using the context of a specific directory.
        /// </summary>
        /// <param name="encryptedFilename">The encrypted filename (including .uvf extension).</param>
        /// <param name="directoryMetadata">The DirectoryMetadata of the parent directory.</param>
        /// <returns>The original plaintext filename.</returns>
        /// <exception cref="ArgumentNullException">If encryptedFilename or directoryMetadata is null.</exception>
        /// <exception cref="InvalidOperationException">If the vault is not initialized correctly.</exception>
        /// <exception cref="ArgumentException">If the encryptedFilename format is invalid.</exception>
        /// <exception cref="AuthenticationFailedException">If the filename authentication fails.</exception>
        /// <exception cref="CryptoException">If decryption fails.</exception>
        public string DecryptFilename(string encryptedFilename, DirectoryMetadata directoryMetadata)
        {
            return VaultDirectoryHelper.DecryptFilenameInternal(_cryptor, directoryMetadata, encryptedFilename);
        }

        /// <summary>
        /// Gets the encrypted directory path for a specific directory.
        /// </summary>
        /// <param name="directoryMetadata">The DirectoryMetadata of the directory.</param>
        /// <returns>The encrypted path (e.g., "d/XX/YYYY...").</returns>
        /// <exception cref="ArgumentNullException">If directoryMetadata is null.</exception>
        /// <exception cref="InvalidOperationException">If the vault is not initialized correctly.</exception>
        public string GetDirectoryPath(DirectoryMetadata directoryMetadata)
        {
            return VaultDirectoryHelper.GetDirectoryPathInternal(_cryptor, directoryMetadata);
        }

        // TODO: Decide if exposing other lower-level operations is useful (e.g., direct chunk access)

    }
}