using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UvfLib.Api;
using UvfLib.Common;

namespace UvfLib.V3
{
    /// <summary>
    /// Implementation of the DirectoryContentCryptor interface for v3 format.
    /// Handles encryption and decryption of directory metadata (dir.uvf files)
    /// and provides access to directory path generation and filename cryptors.
    /// </summary>
    internal sealed class DirectoryContentCryptorImpl : DirectoryContentCryptor
    {
        private readonly RevolvingMasterkey _masterkey;
        private readonly RandomNumberGenerator _random;
        private readonly CryptorImpl _cryptor;

        // JSON serializer options for consistent dir.uvf content
        private static readonly JsonSerializerOptions DirUvfJsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase, // Matches VaultChildItem attributes
            WriteIndented = false // Compact JSON for storage
        };

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
        /// The root directory initially has no children.
        /// </summary>
        /// <returns>The root directory metadata</returns>
        public DirectoryMetadata RootDirectoryMetadata()
        {
            byte[] dirId = _masterkey.GetRootDirId();
            // Root directory starts with no children; they are added as content is processed.
            return new DirectoryMetadataImpl(_masterkey.GetFirstRevision(), dirId, new List<VaultChildItem>());
        }

        /// <summary>
        /// Creates a new directory metadata object, typically for a new subdirectory.
        /// The new directory initially has no children.
        /// </summary>
        /// <returns>The new directory metadata</returns>
        public DirectoryMetadata NewDirectoryMetadata()
        {
            byte[] dirId = new byte[Constants.DIR_ID_SIZE]; // Use defined constant
            _random.GetBytes(dirId);
            // New directories start with no children.
            return new DirectoryMetadataImpl(_masterkey.GetCurrentRevision(), dirId, new List<VaultChildItem>());
        }

        /// <summary>
        /// Decrypts the given directory metadata (content of a dir.uvf file).
        /// </summary>
        /// <param name="ciphertext">The encrypted directory metadata (full content of dir.uvf, including its header).</param>
        /// <param name="directorysOwnDirIdBytes">The raw DirId bytes of the directory to which this ciphertext belongs. This is crucial context.</param>
        /// <returns>The decrypted directory metadata, including its list of children.</returns>
        /// <exception cref="AuthenticationFailedException">If the ciphertext is unauthentic.</exception>
        /// <exception cref="ArgumentException">If ciphertext is invalid.</exception>
        /// <exception cref="JsonException">If the decrypted payload is not valid JSON or cannot be parsed.</exception>
        public DirectoryMetadata DecryptDirectoryMetadata(byte[] ciphertext, byte[] directorysOwnDirIdBytes)
        {
            if (ciphertext == null || ciphertext.Length < FileHeaderImpl.SIZE + Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE) // Minimum size: header + nonce + tag (empty content)
            {
                throw new ArgumentException($"Ciphertext too short. Minimum length is {FileHeaderImpl.SIZE + Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE} bytes.", nameof(ciphertext));
            }
            if (directorysOwnDirIdBytes == null || directorysOwnDirIdBytes.Length != Constants.DIR_ID_SIZE)
            {
                throw new ArgumentException($"Directory's own DirId must be {Constants.DIR_ID_SIZE} bytes.", nameof(directorysOwnDirIdBytes));
            }

            // Decrypt the file header (first 80 bytes of dir.uvf)
            var headerCryptor = _cryptor.FileHeaderCryptor(); // Uses current masterkey revision by default
            FileHeader header = headerCryptor.DecryptHeader(ciphertext.AsSpan(0, FileHeaderImpl.SIZE).ToArray());
            var fileHeaderImpl = FileHeaderImpl.Cast(header);

            // Extract the nonce (12 bytes) which follows the header
            byte[] nonce = ciphertext.AsSpan(FileHeaderImpl.SIZE, Constants.GCM_NONCE_SIZE).ToArray();

            // The actual encrypted content payload is after the header and nonce, and before the GCM tag
            int encryptedPayloadLength = ciphertext.Length - FileHeaderImpl.SIZE - Constants.GCM_NONCE_SIZE - Constants.GCM_TAG_SIZE;
            if (encryptedPayloadLength < 0) {
                 throw new ArgumentException("Invalid ciphertext structure: not enough data for payload and tag after header and nonce.", nameof(ciphertext));
            }
            ReadOnlyMemory<byte> encryptedPayload = new ReadOnlyMemory<byte>(ciphertext, FileHeaderImpl.SIZE + Constants.GCM_NONCE_SIZE, encryptedPayloadLength);
            ReadOnlyMemory<byte> tag = new ReadOnlyMemory<byte>(ciphertext, FileHeaderImpl.SIZE + Constants.GCM_NONCE_SIZE + encryptedPayloadLength, Constants.GCM_TAG_SIZE);

            // Decrypt the content payload using AES-GCM
            byte[] contentKeyBytes = fileHeaderImpl.GetContentKey().GetEncoded();
            using var contentKey = new DestroyableSecretKey(contentKeyBytes, fileHeaderImpl.GetContentKey().Algorithm);
            
            // AAD for dir.uvf content decryption: chunk number (0) + header nonce (from *its own* header) + DirId (of *this* directory)
            byte[] chunkNumberBytes = ByteBuffers.LongToByteArray(0); 
            byte[] headerNonceFromDirUvf = fileHeaderImpl.GetNonce(); 
            
            // The DirId used in AAD for directory content is the DirId of the directory itself.
            byte[] aad = ByteBuffers.Concat(chunkNumberBytes, headerNonceFromDirUvf, directorysOwnDirIdBytes);

            byte[] decryptedPayloadBytes = new byte[encryptedPayloadLength];
            try
            {
                using var aesGcm = new AesGcm(contentKey.GetEncoded());
                aesGcm.Decrypt(nonce, encryptedPayload.Span, tag.Span, decryptedPayloadBytes.AsSpan(), aad);
            }
            catch (CryptographicException ex) // Catches AEADBadTagException
            {
                throw new AuthenticationFailedException("Directory metadata (dir.uvf) decryption failed: authentication tag mismatch.", ex);
            }
            finally
            {
                UvfLib.Common.CryptographicOperations.ZeroMemory(aad);
                UvfLib.Common.CryptographicOperations.ZeroMemory(contentKeyBytes);
            }
            
            // Deserialize the decrypted payload (JSON string) into a list of VaultChildItem
            List<VaultChildItem>? children;
            try
            {
                // Assuming UTF-8 encoding for the JSON string
                string jsonPayload = Encoding.UTF8.GetString(decryptedPayloadBytes);
                children = JsonSerializer.Deserialize<List<VaultChildItem>>(jsonPayload, DirUvfJsonOptions);
                if (children == null) {
                    // Handle case where JSON is "null" or empty array resulting in null
                    children = new List<VaultChildItem>();
                }
            }
            catch (JsonException ex)
            {
                throw new JsonException("Failed to deserialize directory metadata payload (dir.uvf content). Invalid JSON format.", ex);
            }
            finally
            {
                UvfLib.Common.CryptographicOperations.ZeroMemory(decryptedPayloadBytes);
            }

            // Create and return the directory metadata
            // The DirId for this DirectoryMetadataImpl is the one passed in (directorysOwnDirIdBytes)
            return new DirectoryMetadataImpl(fileHeaderImpl.GetSeedId(), directorysOwnDirIdBytes, children);
        }

        /// <summary>
        /// Encrypts the given DirectoryMetadata to produce the content of a dir.uvf file.
        /// </summary>
        /// <param name="directoryMetadata">The directory metadata to encrypt (contains its own DirId and list of children).</param>
        /// <returns>The encrypted binary content for a dir.uvf file.</returns>
        public byte[] EncryptDirectoryMetadata(DirectoryMetadata directoryMetadata)
        {
            DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.Cast(directoryMetadata);
            
            // Serialize the list of children to a JSON string, then to UTF-8 bytes
            string jsonPayload = JsonSerializer.Serialize(metadataImpl.Children, DirUvfJsonOptions);
            byte[] cleartextPayloadBytes = Encoding.UTF8.GetBytes(jsonPayload);

            // Create the header using the directory's own SeedId
            var headerCryptor = _cryptor.FileHeaderCryptor(metadataImpl.SeedId);
            FileHeader header = headerCryptor.Create(); // Creates a new header with a new content key and nonce
            Memory<byte> headerBytes = headerCryptor.EncryptHeader(header);
            var fileHeaderImpl = FileHeaderImpl.Cast(header);

            // Generate a new nonce for this dir.uvf encryption operation
            byte[] nonceForDirUvfEncryption = new byte[Constants.GCM_NONCE_SIZE];
            _random.GetBytes(nonceForDirUvfEncryption);

            // AAD for dir.uvf content encryption: chunk number (0) + header nonce (from *its own* header) + DirId (of *this* directory)
            byte[] chunkNumberBytes = ByteBuffers.LongToByteArray(0);
            byte[] headerNonceFromDirUvf = fileHeaderImpl.GetNonce(); // Nonce from the header we just created
            byte[] dirIdForAad = metadataImpl.GetDirIdBytes(); // DirId of the directory this metadata belongs to

            byte[] aad = ByteBuffers.Concat(chunkNumberBytes, headerNonceFromDirUvf, dirIdForAad);
            
            byte[] encryptedPayloadBytes = new byte[cleartextPayloadBytes.Length];
            byte[] tag = new byte[Constants.GCM_TAG_SIZE];

            byte[] contentKeyBytes = fileHeaderImpl.GetContentKey().GetEncoded();
            using var contentKey = new DestroyableSecretKey(contentKeyBytes, fileHeaderImpl.GetContentKey().Algorithm);

            try
            {
                using var aesGcm = new AesGcm(contentKey.GetEncoded());
                aesGcm.Encrypt(
                    nonceForDirUvfEncryption,
                    cleartextPayloadBytes,
                    encryptedPayloadBytes.AsSpan(),
                    tag,
                    aad);
            }
            finally
            {
                UvfLib.Common.CryptographicOperations.ZeroMemory(cleartextPayloadBytes);
                UvfLib.Common.CryptographicOperations.ZeroMemory(aad);
                UvfLib.Common.CryptographicOperations.ZeroMemory(contentKeyBytes);
            }

            // Combine: header (80 bytes) + nonceForDirUvfEncryption (12 bytes) + encryptedPayloadBytes + tag (16 bytes)
            byte[] result = new byte[headerBytes.Length + nonceForDirUvfEncryption.Length + encryptedPayloadBytes.Length + tag.Length];
            
            headerBytes.CopyTo(new Memory<byte>(result, 0, headerBytes.Length));
            Buffer.BlockCopy(nonceForDirUvfEncryption, 0, result, headerBytes.Length, nonceForDirUvfEncryption.Length);
            Buffer.BlockCopy(encryptedPayloadBytes, 0, result, headerBytes.Length + nonceForDirUvfEncryption.Length, encryptedPayloadBytes.Length);
            Buffer.BlockCopy(tag, 0, result, headerBytes.Length + nonceForDirUvfEncryption.Length + encryptedPayloadBytes.Length, tag.Length);
            
            UvfLib.Common.CryptographicOperations.ZeroMemory(nonceForDirUvfEncryption); // Clean up nonce after use
            // fileHeaderImpl.GetContentKey() and headerNonceFromDirUvf are from 'header' which is disposed by FileHeaderCryptor.

            return result;
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
            // Get the FileNameCryptor for the SeedId specified in the directory's metadata
            FileNameCryptorImpl fileNameCryptor = (FileNameCryptorImpl)_cryptor.FileNameCryptor(metadataImpl.SeedId);
            // Use the raw DirId bytes from the metadata
            string dirIdStr = fileNameCryptor.HashDirectoryId(metadataImpl.GetDirIdBytes());

            return Constants.VAULT_DIR_PREFIX + dirIdStr.Substring(0, 2) + "/" + dirIdStr.Substring(2);
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
            byte[] dirIdBytes = metadataImpl.GetDirIdBytes();
            // Get the FileNameCryptor for the SeedId specified in the directory's metadata
            FileNameCryptorImpl fileNameCryptor = (FileNameCryptorImpl)_cryptor.FileNameCryptor(metadataImpl.SeedId);

            return new NameDecryptor(fileNameCryptor, dirIdBytes);
        }

        /// <summary>
        /// Gets a file name encryptor for the given directory.
        /// </summary>
        /// <param name="directoryMetadata">The directory metadata</param>
        /// <returns>A file name encryptor</returns>
        public Api.IDirectoryContentCryptor.Encrypting FileNameEncryptor(DirectoryMetadata directoryMetadata)
        {
            DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.Cast(directoryMetadata);
            byte[] dirIdBytes = metadataImpl.GetDirIdBytes();
            // Get the FileNameCryptor for the SeedId specified in the directory's metadata
            FileNameCryptorImpl fileNameCryptor = (FileNameCryptorImpl)_cryptor.FileNameCryptor(metadataImpl.SeedId);

            return new NameEncryptor(fileNameCryptor, dirIdBytes);
        }
        
        // Private helper classes for name encryption/decryption context
        private class NameDecryptor : Api.IDirectoryContentCryptor.Decrypting
        {
            private readonly FileNameCryptorImpl _fileNameCryptor;
            private readonly byte[] _dirIdBytes;

            public NameDecryptor(FileNameCryptorImpl fileNameCryptor, byte[] dirIdBytes)
            {
                _fileNameCryptor = fileNameCryptor;
                _dirIdBytes = dirIdBytes;
            }

            public string Decrypt(string ciphertextName)
            {
                // The DirId bytes are used as Associated Data in filename decryption
                return _fileNameCryptor.DecryptFilename(ciphertextName, _dirIdBytes);
            }
        }

        private class NameEncryptor : Api.IDirectoryContentCryptor.Encrypting
        {
            private readonly FileNameCryptorImpl _fileNameCryptor;
            private readonly byte[] _dirIdBytes;

            public NameEncryptor(FileNameCryptorImpl fileNameCryptor, byte[] dirIdBytes)
            {
                _fileNameCryptor = fileNameCryptor;
                _dirIdBytes = dirIdBytes;
            }

            public string Encrypt(string plaintextName)
            {
                // The DirId bytes are used as Associated Data in filename encryption
                return _fileNameCryptor.EncryptFilename(plaintextName, _dirIdBytes);
            }
        }

        // These explicit interface methods are now less relevant if using the contextual encryptor/decryptor above.
        // They could be removed or marked obsolete if the contextual approach is preferred.
        public string EncryptFilename(string cleartextName, string directoryId)
        {
            throw new NotSupportedException("Use contextual FileNameEncryptor obtained via DirectoryMetadata.");
        }

        public string EncryptFilename(string cleartextName, string directoryId, Dictionary<string, string> associatedData)
        {
            throw new NotSupportedException("Use contextual FileNameEncryptor obtained via DirectoryMetadata.");
        }

        public string DecryptFilename(string ciphertextName, string directoryId)
        {
            throw new NotSupportedException("Use contextual FileNameDecryptor obtained via DirectoryMetadata.");
        }

        public string DecryptFilename(string ciphertextName, string directoryId, Dictionary<string, string> associatedData)
        {
            throw new NotSupportedException("Use contextual FileNameDecryptor obtained via DirectoryMetadata.");
        }
    }
}