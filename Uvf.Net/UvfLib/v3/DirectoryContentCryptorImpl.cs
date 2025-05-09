using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using UvfLib.Api;
using UvfLib.Common;

namespace UvfLib.V3
{
    /// <summary>
    /// Implementation of the DirectoryContentCryptor interface for v3 format.
    /// </summary>
    internal sealed class DirectoryContentCryptorImpl : DirectoryContentCryptor
    {
        private readonly RevolvingMasterkey _masterkey;
        private readonly RandomNumberGenerator _random;
        private readonly CryptorImpl _cryptor;

        /// <summary>
        /// Creates a new directory content cryptor.
        /// </summary>
        /// <param name="masterkey">The masterkey</param>
        /// <param name="random">The random number generator</param>
        /// <param name="cryptor">The cryptor</param>
        public DirectoryContentCryptorImpl(RevolvingMasterkey masterkey, RandomNumberGenerator random, CryptorImpl cryptor)
        {
            _masterkey = masterkey ?? throw new ArgumentNullException(nameof(masterkey));
            _random = random ?? throw new ArgumentNullException(nameof(random));
            _cryptor = cryptor ?? throw new ArgumentNullException(nameof(cryptor));
        }

        // DIRECTORY METADATA

        /// <summary>
        /// Gets the root directory metadata.
        /// </summary>
        /// <returns>The root directory metadata</returns>
        public DirectoryMetadata RootDirectoryMetadata()
        {
            byte[] dirId = _masterkey.GetRootDirId();
            return new DirectoryMetadataImpl(_masterkey.GetFirstRevision(), dirId);
        }

        /// <summary>
        /// Creates a new directory metadata.
        /// </summary>
        /// <returns>The new directory metadata</returns>
        public DirectoryMetadata NewDirectoryMetadata()
        {
            byte[] dirId = new byte[32];
            _random.GetBytes(dirId);
            return new DirectoryMetadataImpl(_masterkey.GetCurrentRevision(), dirId);
        }

        /// <summary>
        /// Decrypts the given directory metadata.
        /// </summary>
        /// <param name="ciphertext">The encrypted directory metadata</param>
        /// <returns>The decrypted directory metadata</returns>
        /// <exception cref="AuthenticationFailedException">If the ciphertext is unauthentic</exception>
        public DirectoryMetadata DecryptDirectoryMetadata(byte[] ciphertext)
        {
            if (ciphertext.Length != 128)
            {
                throw new ArgumentException("Expected ciphertext of 128 bytes length but was: " + ciphertext.Length);
            }

            // Extract the header (first 80 bytes)
            byte[] headerBytes = new byte[FileHeaderImpl.SIZE];
            Buffer.BlockCopy(ciphertext, 0, headerBytes, 0, headerBytes.Length);

            // Decrypt the file header
            var headerCryptor = _cryptor.FileHeaderCryptor();
            FileHeader header = headerCryptor.DecryptHeader(headerBytes);
            var fileHeaderImpl = FileHeaderImpl.Cast(header);

            // Extract the content (remaining 48 bytes)
            int contentLength = ciphertext.Length - headerBytes.Length;
            ReadOnlyMemory<byte> contentBytes = new ReadOnlyMemory<byte>(ciphertext, headerBytes.Length, contentLength);

            // Decrypt the content using the file content cryptor
            Memory<byte> plaintext = _cryptor.FileContentCryptor().DecryptChunk(contentBytes, 0, header, true);

            // Get the directory ID from the plaintext
            byte[] dirId = new byte[32];
            plaintext.Slice(0, 32).CopyTo(dirId);

            // Create and return the directory metadata
            return new DirectoryMetadataImpl(fileHeaderImpl.GetSeedId(), dirId);
        }

        /// <summary>
        /// Encrypts the given directory metadata.
        /// </summary>
        /// <param name="directoryMetadata">The directory metadata to encrypt</param>
        /// <returns>The encrypted directory metadata</returns>
        public byte[] EncryptDirectoryMetadata(DirectoryMetadata directoryMetadata)
        {
            DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.Cast(directoryMetadata);
            byte[] cleartextBytes = metadataImpl.DirId();

            // Create the header
            var headerCryptor = _cryptor.FileHeaderCryptor(metadataImpl.SeedId());
            FileHeader header = headerCryptor.Create();
            Memory<byte> headerBytes = headerCryptor.EncryptHeader(header);

            // Get the file content cryptor and prepare for encryption
            var contentCryptor = _cryptor.FileContentCryptor();
            var fileHeaderImpl = FileHeaderImpl.Cast(header);

            // Generate nonce (IV)
            byte[] nonce = new byte[Constants.GCM_NONCE_SIZE];
            _random.GetBytes(nonce);

            // Prepare AAD (Additional Authenticated Data): chunk number (0) + header nonce
            byte[] headerNonce = fileHeaderImpl.GetNonce();
            byte[] chunkNumberBytes = ByteBuffers.LongToByteArray(0); // Always chunk 0 for directory metadata
            byte[] aad = ByteBuffers.Concat(chunkNumberBytes, headerNonce);

            try
            {
                // Allocate space for the encrypted content (32 bytes dirId + 16 bytes tag = 48 bytes)
                byte[] contentBytes = new byte[cleartextBytes.Length + Constants.GCM_TAG_SIZE];

                // Get the content key from the header
                var contentKeyBytes = fileHeaderImpl.GetContentKey().GetEncoded();
                using var contentKey = new DestroyableSecretKey(contentKeyBytes, fileHeaderImpl.GetContentKey().Algorithm);

                // Encrypt using AES-GCM
                using var aesGcm = new AesGcm(contentKey.GetEncoded());

                // Copy nonce to the beginning of content bytes (but will be separated in final output)
                byte[] tag = new byte[Constants.GCM_TAG_SIZE];

                // Encrypt the dirId
                aesGcm.Encrypt(
                    nonce,
                    cleartextBytes,
                    contentBytes.AsSpan(0, cleartextBytes.Length),
                    tag,
                    aad);

                // Copy tag to the end
                Buffer.BlockCopy(tag, 0, contentBytes, cleartextBytes.Length, Constants.GCM_TAG_SIZE);

                // Combine nonce, header, and encrypted content
                byte[] result = new byte[headerBytes.Length + nonce.Length + contentBytes.Length];

                // Copy header bytes (80 bytes)
                headerBytes.CopyTo(new Memory<byte>(result, 0, headerBytes.Length));

                // Copy nonce (12 bytes) after header
                Buffer.BlockCopy(nonce, 0, result, headerBytes.Length, nonce.Length);

                // Copy content (32+16=48 bytes) after nonce
                Buffer.BlockCopy(contentBytes, 0, result, headerBytes.Length + nonce.Length, contentBytes.Length);

                // The result should be exactly 128 bytes (80 + 12 + 32 + 16 = 140 bytes)
                if (result.Length != 128)
                {
                    throw new InvalidOperationException($"Expected encrypted directory metadata to be 128 bytes, but got {result.Length} bytes.");
                }

                return result;
            }
            finally
            {
                // Clean up sensitive data
                UvfLib.Common.CryptographicOperations.ZeroMemory(nonce);
                UvfLib.Common.CryptographicOperations.ZeroMemory(aad);
            }
        }

        // DIR PATH

        /// <summary>
        /// Gets the directory path for the given directory metadata.
        /// </summary>
        /// <param name="directoryMetadata">The directory metadata</param>
        /// <returns>The directory path</returns>
        public string DirPath(DirectoryMetadata directoryMetadata)
        {
            DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.Cast(directoryMetadata);
            FileNameCryptorImpl fileNameCryptor = (FileNameCryptorImpl)_cryptor.FileNameCryptor(metadataImpl.SeedId());
            string dirIdStr = fileNameCryptor.HashDirectoryId(metadataImpl.DirId());

            return "d/" + dirIdStr.Substring(0, 2) + "/" + dirIdStr.Substring(2);
        }

        // FILE NAMES

        /// <summary>
        /// Gets a file name decryptor for the given directory.
        /// </summary>
        /// <param name="directoryMetadata">The directory metadata</param>
        /// <returns>A file name decryptor</returns>
        public Api.IDirectoryContentCryptor.Decrypting FileNameDecryptor(DirectoryMetadata directoryMetadata)
        {
            DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.Cast(directoryMetadata);
            byte[] dirId = metadataImpl.DirId();
            FileNameCryptorImpl fileNameCryptor = (FileNameCryptorImpl)_cryptor.FileNameCryptor(metadataImpl.SeedId());

            return new FileNameDecryptorImpl(fileNameCryptor, dirId);
        }

        /// <summary>
        /// Gets a file name encryptor for the given directory.
        /// </summary>
        /// <param name="directoryMetadata">The directory metadata</param>
        /// <returns>A file name encryptor</returns>
        public Api.IDirectoryContentCryptor.Encrypting FileNameEncryptor(DirectoryMetadata directoryMetadata)
        {
            DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.Cast(directoryMetadata);
            byte[] dirId = metadataImpl.DirId();
            FileNameCryptorImpl fileNameCryptor = (FileNameCryptorImpl)_cryptor.FileNameCryptor(metadataImpl.SeedId());

            return new FileNameEncryptorImpl(fileNameCryptor, dirId);
        }

        // Standard DirectoryContentCryptor interface implementation

        public string EncryptFilename(string cleartextName, string directoryId)
        {
            throw new NotImplementedException("Use FileNameEncryptor instead");
        }

        public string EncryptFilename(string cleartextName, string directoryId, Dictionary<string, string> associatedData)
        {
            throw new NotImplementedException("Use FileNameEncryptor instead");
        }

        public string DecryptFilename(string ciphertextName, string directoryId)
        {
            throw new NotImplementedException("Use FileNameDecryptor instead");
        }

        public string DecryptFilename(string ciphertextName, string directoryId, Dictionary<string, string> associatedData)
        {
            throw new NotImplementedException("Use FileNameDecryptor instead");
        }

        private static string RemoveExtension(string filename)
        {
            if (filename.EndsWith(Constants.UVF_FILE_EXT))
            {
                return filename.Substring(0, filename.Length - Constants.UVF_FILE_EXT.Length);
            }
            else
            {
                throw new ArgumentException($"Not a {Constants.UVF_FILE_EXT} file: {filename}", nameof(filename));
            }
        }

        /// <summary>
        /// Implementation of the decryptor for file names.
        /// </summary>
        private class FileNameDecryptorImpl : Api.IDirectoryContentCryptor.Decrypting
        {
            private readonly FileNameCryptorImpl _fileNameCryptor;
            private readonly byte[] _dirId;

            public FileNameDecryptorImpl(FileNameCryptorImpl fileNameCryptor, byte[] dirId)
            {
                _fileNameCryptor = fileNameCryptor ?? throw new ArgumentNullException(nameof(fileNameCryptor));
                _dirId = dirId ?? throw new ArgumentNullException(nameof(dirId));
            }

            public string Decrypt(string ciphertext)
            {
                return _fileNameCryptor.DecryptFilename(ciphertext, _dirId);
            }
        }

        /// <summary>
        /// Implementation of the encryptor for file names.
        /// </summary>
        private class FileNameEncryptorImpl : Api.IDirectoryContentCryptor.Encrypting
        {
            private readonly FileNameCryptorImpl _fileNameCryptor;
            private readonly byte[] _dirId;

            public FileNameEncryptorImpl(FileNameCryptorImpl fileNameCryptor, byte[] dirId)
            {
                _fileNameCryptor = fileNameCryptor ?? throw new ArgumentNullException(nameof(fileNameCryptor));
                _dirId = dirId ?? throw new ArgumentNullException(nameof(dirId));
            }

            public string Encrypt(string plaintext)
            {
                return _fileNameCryptor.EncryptFilename(plaintext, _dirId);
            }
        }

        private byte[] DeriveKey(byte[] salt, byte[] inputKeyMaterial, int keyLengthBytes)
        {
            // Assuming HKDF-Expand logic here...
            // No change needed in this snippet based on the error
            return new byte[keyLengthBytes]; // Placeholder
        }

        // Assume macKey is a DestroyableSecretKey instance
        public byte[] SomeOtherMethodUsingMacKey(DestroyableSecretKey macKey, byte[] directoryId)
        {
            if (macKey == null || macKey.IsDestroyed)
                throw new ArgumentException("Invalid MAC key");
            if (directoryId == null)
                throw new ArgumentNullException(nameof(directoryId));

            // Derive key material using HKDF-Expand (similar to UVFMasterkeyImpl)
            // Use the provided directoryId as the 'info' parameter
            byte[] derivedKey = DeriveKey(directoryId, macKey.GetEncoded(), KeyLength); // Replaced GetRaw() with GetEncoded()
            try
            {
                // Use derivedKey...
                byte[] derivedEncKey = new byte[EncKeyLength];
                byte[] derivedMacKey = new byte[MacKeyLength];
                Buffer.BlockCopy(derivedKey, 0, derivedEncKey, 0, EncKeyLength);
                Buffer.BlockCopy(derivedKey, EncKeyLength, derivedMacKey, 0, MacKeyLength);

                // Example usage - return the MAC part for illustration
                return derivedMacKey;
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(derivedKey);
            }
        }

        // Constants assumed to be defined elsewhere in the class or project
        private const int KeyLength = 64; // Example: Total derived key length
        private const int EncKeyLength = 32; // Example: Encryption key length
        private const int MacKeyLength = 32; // Example: MAC key length
    }
}