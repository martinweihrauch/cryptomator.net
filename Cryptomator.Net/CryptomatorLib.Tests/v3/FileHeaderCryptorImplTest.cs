using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using CommonConstants = CryptomatorLib.Common.Constants;
using CryptomatorLib.Tests.Common;
using CryptomatorLib.V3;
using V3Constants = CryptomatorLib.V3.Constants;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Moq;

namespace CryptomatorLib.Tests.V3
{
    [TestClass]
    public class FileHeaderCryptorImplTest
    {
        // Define test data for masterkey creation - same as in Java tests for consistency
        private static readonly Dictionary<int, byte[]> SEEDS = new Dictionary<int, byte[]>
        {
            { -1540072521, Convert.FromBase64String("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU=".Replace('-', '+').Replace('_', '/')) }
        };
        private static readonly byte[] KDF_SALT = Convert.FromBase64String("HE4OP-2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY=".Replace('-', '+').Replace('_', '/'));
        private static readonly UVFMasterkey MASTERKEY = new UVFMasterkeyImpl(SEEDS, KDF_SALT, -1540072521, -1540072521);

        private FileHeaderCryptorImpl _headerCryptor;
        private RandomNumberGenerator _random;

        [TestInitialize]
        public void Setup()
        {
            _random = SecureRandomMock.NULL_RANDOM;
            _headerCryptor = new FileHeaderCryptorImpl(MASTERKEY, _random, -1540072521);
        }

        [TestMethod]
        [DisplayName("Test Create New Header")]
        public void TestCreateNewHeader()
        {
            // Act
            FileHeader header = _headerCryptor.Create();

            // Assert
            Assert.IsNotNull(header);
            Assert.IsInstanceOfType(header, typeof(FileHeaderImpl));

            // Since we're using a deterministic RNG for testing, we should be able to verify
            // that the header has predictable content
            var headerImpl = (FileHeaderImpl)header;

            // Verify the seed ID matches our expected value
            Assert.AreEqual(-1540072521, headerImpl.GetSeedId());

            // Now convert the header to bytes and decrypt it again to verify it's valid
            Memory<byte> encrypted = _headerCryptor.EncryptHeader(header);
            FileHeader decrypted = _headerCryptor.DecryptHeader(encrypted);

            // Verify the decrypted header has the same seed ID
            Assert.AreEqual(headerImpl.GetSeedId(), ((FileHeaderImpl)decrypted).GetSeedId());
        }

        [TestMethod]
        [DisplayName("Test Encrypted Decrypted Header Equals Original")]
        public void TestEncryptedDecryptedHeaderEqualsOriginal()
        {
            // First create a header
            FileHeader header = _headerCryptor.Create();

            // Get the content key from the header (needed for comparison later)
            DestroyableSecretKey originalKey = new DestroyableSecretKey(((FileHeaderImpl)header).GetContentKey().GetEncoded(), "AES");

            try
            {
                // Encrypt the header
                Memory<byte> encryptedHeader = _headerCryptor.EncryptHeader(header);

                // Decrypt the header
                FileHeader decryptedHeader = _headerCryptor.DecryptHeader(encryptedHeader);

                // Assert that the decrypted header has the same properties
                DestroyableSecretKey decryptedKey = ((FileHeaderImpl)decryptedHeader).GetContentKey();
                Assert.AreEqual(((FileHeaderImpl)header).GetSeedId(), ((FileHeaderImpl)decryptedHeader).GetSeedId());

                // Compare the content key bytes
                CollectionAssert.AreEqual(originalKey.GetEncoded(), decryptedKey.GetEncoded());
            }
            finally
            {
                originalKey?.Dispose();
            }
        }

        [TestMethod]
        [DisplayName("Test Header Size")]
        public void TestHeaderSize()
        {
            // Verify that the header size matches the constant in FileHeaderImpl
            Assert.AreEqual(FileHeaderImpl.SIZE, _headerCryptor.HeaderSize());
        }

        [TestMethod]
        [DisplayName("Test Decrypt Header With Invalid Magic Bytes")]
        public void TestDecryptHeaderWithInvalidMagicBytes()
        {
            // Create an encrypted header
            FileHeader header = _headerCryptor.Create();
            Memory<byte> encryptedHeader = _headerCryptor.EncryptHeader(header);

            // Tamper with the magic bytes
            byte[] tamperedHeader = encryptedHeader.ToArray();
            tamperedHeader[0] ^= 0xFF; // Flip all bits in the first byte

            // Attempt to decrypt the tampered header
            Assert.ThrowsException<ArgumentException>(() =>
                _headerCryptor.DecryptHeader(new ReadOnlyMemory<byte>(tamperedHeader)));
        }

        [TestMethod]
        [DisplayName("Test Decrypt Header With Tampered Content")]
        public void TestDecryptHeaderWithTamperedContent()
        {
            // Create an encrypted header
            FileHeader header = _headerCryptor.Create();
            Memory<byte> encryptedHeader = _headerCryptor.EncryptHeader(header);

            // Tamper with the content (avoid magic bytes at the beginning)
            byte[] tamperedHeader = encryptedHeader.ToArray();
            tamperedHeader[V3Constants.UVF_MAGIC_BYTES.Length + 5] ^= 0x01; // Flip one bit in the content

            // Attempt to decrypt the tampered header
            Assert.ThrowsException<AuthenticationFailedException>(() =>
                _headerCryptor.DecryptHeader(new ReadOnlyMemory<byte>(tamperedHeader)));
        }

        [TestMethod]
        [DisplayName("Test Decrypt Header With Too Small Size")]
        public void TestDecryptHeaderWithTooSmallSize()
        {
            // Create a too-small buffer for the header
            byte[] tooSmallHeader = new byte[FileHeaderImpl.SIZE - 1];

            // Attempt to decrypt it
            Assert.ThrowsException<ArgumentException>(() =>
                _headerCryptor.DecryptHeader(new ReadOnlyMemory<byte>(tooSmallHeader)));
        }

        [TestMethod]
        [DisplayName("Test Encrypt Header With Null")]
        public void TestEncryptHeaderWithNull()
        {
            // Attempt to encrypt a null header
            Assert.ThrowsException<ArgumentNullException>(() =>
                _headerCryptor.EncryptHeader(null));
        }
    }
}