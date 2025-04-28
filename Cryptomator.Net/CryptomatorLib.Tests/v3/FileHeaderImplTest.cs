using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using CryptomatorLib.V3;
using Moq;
using System;
using System.Security.Cryptography;

namespace CryptomatorLib.Tests.V3
{
    [TestClass]
    public class FileHeaderImplTest
    {
        [TestMethod]
        [DisplayName("Test Cast From FileHeader Interface")]
        public void TestCast()
        {
            // Create a new header
            byte[] nonce = new byte[FileHeaderImpl.NONCE_LEN];
            DestroyableSecretKey contentKey = new DestroyableSecretKey(new byte[FileHeaderImpl.CONTENT_KEY_LEN], "AES");
            FileHeaderImpl header = new FileHeaderImpl(42, nonce, contentKey);

            // Cast it as the interface type
            FileHeader fileHeader = header;

            // Now cast it back
            FileHeaderImpl castedHeader = FileHeaderImpl.Cast(fileHeader);

            // Verify the cast worked
            Assert.AreSame(header, castedHeader);
        }

        [TestMethod]
        [DisplayName("Test Cast Invalid Type")]
        public void TestCastInvalidType()
        {
            // Create a mock implementation of FileHeader that isn't a FileHeaderImpl
            var mockHeader = new Mock<FileHeader>();

            // Try to cast it - should throw
            Assert.ThrowsException<InvalidCastException>(() => FileHeaderImpl.Cast(mockHeader.Object));
        }

        [TestMethod]
        [DisplayName("Test Cast Null")]
        public void TestCastNull()
        {
            // Try to cast null - should throw
            Assert.ThrowsException<ArgumentNullException>(() => FileHeaderImpl.Cast(null));
        }

        [TestMethod]
        [DisplayName("Test Constructor And Getters")]
        public void TestConstructorAndGetters()
        {
            // Arrange
            int seedId = 12345;
            byte[] nonce = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            byte[] keyBytes = new byte[32];
            RandomNumberGenerator.Fill(keyBytes);
            var contentKey = new DestroyableSecretKey(keyBytes, "AES");

            // Act
            FileHeaderImpl header = new FileHeaderImpl(seedId, nonce, contentKey);

            // Assert
            Assert.AreEqual(seedId, header.GetSeedId());
            CollectionAssert.AreEqual(nonce, header.GetNonce());

            // Get the content key and verify it matches the input
            using (DestroyableSecretKey retrievedKey = header.GetContentKey())
            {
                CollectionAssert.AreEqual(keyBytes, retrievedKey.GetEncoded());
            }
        }
    }
}