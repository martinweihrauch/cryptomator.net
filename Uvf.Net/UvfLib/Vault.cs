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
using UvfLib.Jwe; // For JweVaultManager and UvfMasterkeyPayload
using System.IO; // For File operations
using System.Text; // For Encoding
using System.Text.Json; // For JsonSerializer

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("UvfLib.Tests")]

namespace UvfLib
{
    /// <summary>
    /// Represents an unlocked Uvf vault and provides high-level access
    /// to its cryptographic operations.
    /// </summary>
    public sealed class Vault : IDisposable
    {
        private readonly Cryptor _cryptor;
        private readonly PerpetualMasterkey? _perpetualMasterkey; // For older formats or if UVFMasterkey can provide one
        private readonly RevolvingMasterkey _revolvingMasterkey; // Main masterkey for UVF
        private static readonly RandomNumberGenerator CsPrng = RandomNumberGenerator.Create(); // Static instance for loading
        private bool _disposed = false;

        /// <summary>
        /// Gets the file content cryptor.
        /// </summary>
        /// <exception cref="InvalidOperationException">If the cryptor or file content cryptor is not available.</exception>
        public IFileContentCryptor FileContentCryptor
        {
            get
            {
                if (_disposed) throw new ObjectDisposedException(nameof(Vault));
                if (_cryptor == null) throw new InvalidOperationException("Cryptor not initialized.");
                var fcCryptor = _cryptor.FileContentCryptor();
                if (fcCryptor == null) throw new InvalidOperationException("File content cryptor not available.");
                return fcCryptor;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Vault"/> class.
        /// Private constructor to force usage of static factory methods like Load.
        /// </summary>
        /// <param name="cryptor">The initialized cryptor for this vault.</param>
        /// <param name="masterkey">The underlying masterkey.</param>
        private Vault(Cryptor cryptor, PerpetualMasterkey masterkey)
        {
            _cryptor = cryptor ?? throw new ArgumentNullException(nameof(cryptor));
            _perpetualMasterkey = masterkey ?? throw new ArgumentNullException(nameof(masterkey));
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Vault"/> class with both masterkey types.
        /// </summary>
        /// <param name="cryptor">The initialized cryptor for this vault.</param>
        /// <param name="masterkey">The perpetual masterkey.</param>
        /// <param name="revolvingMasterkey">The revolving masterkey used by the cryptor.</param>
        private Vault(Cryptor cryptor, PerpetualMasterkey masterkey, RevolvingMasterkey revolvingMasterkey)
        {
            _cryptor = cryptor ?? throw new ArgumentNullException(nameof(cryptor));
            _perpetualMasterkey = masterkey ?? throw new ArgumentNullException(nameof(masterkey));
            _revolvingMasterkey = revolvingMasterkey ?? throw new ArgumentNullException(nameof(revolvingMasterkey));
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Vault"/> class with only the revolving masterkey.
        /// </summary>
        /// <param name="cryptor">The initialized cryptor for this vault.</param>
        /// <param name="revolvingMasterkey">The revolving masterkey used by the cryptor.</param>
        private Vault(Cryptor cryptor, RevolvingMasterkey revolvingMasterkey)
        {
            _cryptor = cryptor ?? throw new ArgumentNullException(nameof(cryptor));
            _revolvingMasterkey = revolvingMasterkey ?? throw new ArgumentNullException(nameof(revolvingMasterkey));
            _perpetualMasterkey = null; // Or try to adapt if RevolvingMasterkey can provide a Perpetual variant
        }

        /// <summary>
        /// Releases all resources used by the Vault.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                // Dispose the masterkeys
                _perpetualMasterkey?.Dispose();
                
                if (_revolvingMasterkey != null && _revolvingMasterkey is IDisposable disposable)
                {
                    disposable.Dispose();
                }

                // Dispose the cryptor if it implements IDisposable
                if (_cryptor is IDisposable cryptorDisposable)
                {
                    cryptorDisposable.Dispose();
                }

                _disposed = true;
            }
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
        /// Creates the encrypted JWE content for a new UVF vault file.
        /// </summary>
        /// <param name="password">The password for the new vault.</param>
        /// <returns>A byte array containing the encrypted UVF vault file data (JWE string).</returns>
        public static byte[] CreateNewUvfVaultFileContent(string password)
        {
            // Delegate to VaultKeyHelper, pepper is not used for JWE in this simplified setup
            return VaultKeyHelper.CreateNewVaultKeyFileContentInternal(password, null);
        }

        /// <summary>
        /// Creates a new UVF vault file (vault.uvf) at the specified path.
        /// </summary>
        /// <param name="filePath">The path where the vault.uvf file will be created.</param>
        /// <param name="password">The password for the new vault.</param>
        public static void CreateNewUvfVault(string filePath, string password)
        {
            if (string.IsNullOrEmpty(filePath)) throw new ArgumentNullException(nameof(filePath));
            byte[] uvfFileContent = CreateNewUvfVaultFileContent(password);
            File.WriteAllBytes(filePath, uvfFileContent);
        }

        /// <summary>
        /// Loads a UVF vault using its JWE-formatted key file and password.
        /// </summary>
        /// <param name="uvfFilePath">The path to the vault.uvf file.</param>
        /// <param name="password">The vault password.</param>
        /// <returns>An initialized Vault instance ready for operations.</returns>
        public static Vault LoadUvfVault(string uvfFilePath, string password)
        {
            if (string.IsNullOrEmpty(uvfFilePath)) throw new ArgumentNullException(nameof(uvfFilePath));
            if (!File.Exists(uvfFilePath)) throw new FileNotFoundException("UVF vault file not found.", uvfFilePath);
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));

            string jweString = File.ReadAllText(uvfFilePath, Encoding.UTF8);
            UVFMasterkey? uvfMasterkey = null;
            try
            {
                UvfMasterkeyPayload payload = JweVaultManager.LoadVaultPayload(jweString, password);
                string jsonPayloadString = JsonSerializer.Serialize(payload); 
                
                // Api.UVFMasterkey.FromDecryptedPayload is the entry point that leads to UVFMasterkeyImpl
                uvfMasterkey = (UVFMasterkey)Api.UVFMasterkey.FromDecryptedPayload(jsonPayloadString);

                // Assuming UVF_DRAFT is the correct scheme for your V3 implementation
                CryptorProvider provider = CryptorProvider.ForScheme(CryptorProvider.Scheme.UVF_DRAFT);
                Cryptor cryptor = provider.Provide(uvfMasterkey, CsPrng);

                // Use the constructor that primarily takes RevolvingMasterkey for UVF
                return new Vault(cryptor, uvfMasterkey);
            }
            catch (Exception ex) when (ex is Jose.JoseException || ex is JsonException || ex is InvalidOperationException || ex is ArgumentException)
            {
                (uvfMasterkey as IDisposable)?.Dispose();
                // Wrap in a standard library exception type if desired, e.g., MasterkeyLoadingFailedException
                throw new MasterkeyLoadingFailedException($"Failed to load UVF vault from {uvfFilePath}. Check password or file integrity.", ex);
            }
            catch
            {
                (uvfMasterkey as IDisposable)?.Dispose();
                throw; // Re-throw other unexpected exceptions
            }
        }

        /// <summary>
        /// Loads a vault's Cryptor instance using the master key file content and password (Cryptomator old format).
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
        public static Vault LoadCryptomatorVault(byte[] encryptedKeyFileContent, string password, byte[]? pepper = null)
        {
            if (encryptedKeyFileContent == null) throw new ArgumentNullException(nameof(encryptedKeyFileContent));
            if (password == null) throw new ArgumentNullException(nameof(password));
            byte[] effectivePepper = pepper ?? Array.Empty<byte>();

            MasterkeyFile masterkeyFile = MasterkeyFile.FromJson(encryptedKeyFileContent);
            var keyAccessor = new MasterkeyFileAccess(effectivePepper, CsPrng);
            PerpetualMasterkey perpetualMasterkey = keyAccessor.Unlock(masterkeyFile, password);
            RevolvingMasterkey? revolving = null;
            try 
            {
                byte[] kdfSalt = new byte[32];
                CsPrng.GetBytes(kdfSalt);
                int seedId = 1;
                byte[] rawKey = perpetualMasterkey.GetRaw();
                try
                {
                    Dictionary<int, byte[]> seeds = new Dictionary<int, byte[]> { { seedId, rawKey } };
                    revolving = new UvfLib.V3.UVFMasterkeyImpl(seeds, kdfSalt, seedId, seedId);
                }
                finally
                {
                    UvfLib.Common.CryptographicOperations.ZeroMemory(rawKey);
                }
                CryptorProvider.Scheme scheme;
                if (masterkeyFile.VaultVersion >= 8)
                {
                    scheme = CryptorProvider.Scheme.UVF_DRAFT;
                }
                else
                {
                    var dummyUri = new Uri("file://masterkey.cryptomator");
                    var detectedFormat = VaultFormat.Unknown;
                    string errorMessage = $"Unsupported vault version ({masterkeyFile.VaultVersion}) or unable to determine scheme.";
                    throw new UnsupportedVaultFormatException(dummyUri, detectedFormat, errorMessage);
                }
                CryptorProvider provider = CryptorProvider.ForScheme(scheme);
                Cryptor cryptor = provider.Provide(revolving, CsPrng);
                return new Vault(cryptor, perpetualMasterkey, revolving);
            }
            catch (Exception)
            {
                if (revolving != null && revolving is IDisposable disposableRev)
                {
                    disposableRev.Dispose();
                }
                perpetualMasterkey.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Changes the password for an existing JWE UVF vault file's content.
        /// </summary>
        /// <param name="encryptedUvfFileContent">The current byte content of the vault.uvf file.</param>
        /// <param name="oldPassword">The current vault password.</param>
        /// <param name="newPassword">The desired new vault password.</param>
        /// <returns>A byte array containing the newly encrypted vault.uvf file data.</returns>
        /// <exception cref="ArgumentNullException">If file content or passwords are null.</exception>
        /// <exception cref="InvalidPassphraseException">If the oldPassword is incorrect.</exception>
        public static byte[] ChangeUvfVaultPassword(byte[] encryptedUvfFileContent, string oldPassword, string newPassword)
        {
            // Delegate to VaultKeyHelper, pepper is not used for JWE in this simplified setup
            return VaultKeyHelper.ChangeVaultPasswordInternal(encryptedUvfFileContent, oldPassword, newPassword, null);
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

        /// <summary>
        /// Provides access to the underlying Cryptor instance.
        /// Primarily for advanced use cases or when direct access to cryptor sub-components is needed.
        /// </summary>
        /// <exception cref="InvalidOperationException">If the cryptor is not initialized.</exception>
        /// <exception cref="ObjectDisposedException">If the Vault has been disposed.</exception>
        internal Cryptor Cryptor // Made internal for helpers like VaultStreamHelper
        {
            get
            {
                if (_disposed) throw new ObjectDisposedException(nameof(Vault));
                if (_cryptor == null) throw new InvalidOperationException("Cryptor not initialized.");
                return _cryptor;
            }
        }

    }
}