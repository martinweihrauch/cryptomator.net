using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using CryptomatorLib.Api;
using CryptomatorLib.Common;

namespace CryptomatorLib.V3
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
                throw new ArgumentException($"Invalid dir.uvf length: {ciphertext.Length}", nameof(ciphertext));
            }

            int headerSize = _cryptor.FileHeaderCryptor().HeaderSize();
            Span<byte> headerBytes = ciphertext.AsSpan(0, headerSize);
            Span<byte> contentBytes = ciphertext.AsSpan(headerSize);

            // Convert to ReadOnlyMemory for DecryptHeader
            var headerMemory = new ReadOnlyMemory<byte>(headerBytes.ToArray());

            FileHeader header = _cryptor.FileHeaderCryptor().DecryptHeader(headerMemory);
            FileHeaderImpl headerImpl = FileHeaderImpl.Cast(header);

            var plaintext = _cryptor.FileContentCryptor().DecryptChunk(contentBytes.ToArray(), 0, header, true);

            if (plaintext.Length != 32)
            {
                throw new InvalidOperationException("Expected 32 bytes of plaintext but got " + plaintext.Length);
            }

            byte[] dirId = new byte[32];
            Buffer.BlockCopy(plaintext.ToArray(), 0, dirId, 0, 32);

            return new DirectoryMetadataImpl(headerImpl.GetSeedId(), dirId);
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

            FileHeader header = _cryptor.FileHeaderCryptor(metadataImpl.SeedId()).Create();

            // Convert to byte[] from Memory<byte>
            Memory<byte> headerBytesMemory = _cryptor.FileHeaderCryptor().EncryptHeader(header);
            byte[] headerBytes = headerBytesMemory.ToArray();

            Memory<byte> contentBytesMemory = _cryptor.FileContentCryptor().EncryptChunk(cleartextBytes, 0, header);
            byte[] contentBytes = contentBytesMemory.ToArray();

            byte[] result = new byte[headerBytes.Length + contentBytes.Length];
            Buffer.BlockCopy(headerBytes, 0, result, 0, headerBytes.Length);
            Buffer.BlockCopy(contentBytes, 0, result, headerBytes.Length, contentBytes.Length);

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
    }
}