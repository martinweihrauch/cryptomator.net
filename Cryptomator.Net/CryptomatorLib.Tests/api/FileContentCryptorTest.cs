using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Api;
using Moq;
using System;

namespace CryptomatorLib.Tests.Api
{
    [TestClass]
    public class FileContentCryptorTest
    {
        private Mock<FileContentCryptor> _contentCryptor;

        [TestInitialize]
        public void Setup()
        {
            _contentCryptor = new Mock<FileContentCryptor>();
            _contentCryptor.Setup(c => c.CleartextChunkSize()).Returns(32);
            _contentCryptor.Setup(c => c.CiphertextChunkSize()).Returns(40);

            // Use CallBase to allow the interface's default implementation to be called
            _contentCryptor.Setup(c => c.CleartextSize(It.IsAny<long>())).CallBase();
            _contentCryptor.Setup(c => c.CiphertextSize(It.IsAny<long>())).CallBase();
        }

        [DataTestMethod]
        [DataRow(0, 0, DisplayName = "CleartextSize(0) == 0")]
        [DataRow(9, 1, DisplayName = "CleartextSize(9) == 1")]
        [DataRow(39, 31, DisplayName = "CleartextSize(39) == 31")]
        [DataRow(40, 32, DisplayName = "CleartextSize(40) == 32")]
        [DataRow(49, 33, DisplayName = "CleartextSize(49) == 33")]
        [DataRow(50, 34, DisplayName = "CleartextSize(50) == 34")]
        [DataRow(79, 63, DisplayName = "CleartextSize(79) == 63")]
        [DataRow(80, 64, DisplayName = "CleartextSize(80) == 64")]
        [DataRow(89, 65, DisplayName = "CleartextSize(89) == 65")]
        public void TestCleartextSize(int ciphertextSize, int expectedCleartextSize)
        {
            // Act
            long result = _contentCryptor.Object.CleartextSize(ciphertextSize);

            // Assert
            Assert.AreEqual(expectedCleartextSize, result);
        }

        [DataTestMethod]
        [DataRow(-1, DisplayName = "CleartextSize(-1) throws")]
        [DataRow(1, DisplayName = "CleartextSize(1) throws")]
        [DataRow(8, DisplayName = "CleartextSize(8) throws")]
        [DataRow(41, DisplayName = "CleartextSize(41) throws")]
        [DataRow(48, DisplayName = "CleartextSize(48) throws")]
        [DataRow(81, DisplayName = "CleartextSize(81) throws")]
        [DataRow(88, DisplayName = "CleartextSize(88) throws")]
        public void TestCleartextSizeWithInvalidCiphertextSize(int invalidCiphertextSize)
        {
            // Act & Assert
            Assert.ThrowsException<ArgumentException>(() =>
                _contentCryptor.Object.CleartextSize(invalidCiphertextSize));
        }

        [DataTestMethod]
        [DataRow(0, 0, DisplayName = "CiphertextSize(0) == 0")]
        [DataRow(1, 9, DisplayName = "CiphertextSize(1) == 9")]
        [DataRow(31, 39, DisplayName = "CiphertextSize(31) == 39")]
        [DataRow(32, 40, DisplayName = "CiphertextSize(32) == 40")]
        [DataRow(33, 49, DisplayName = "CiphertextSize(33) == 49")]
        [DataRow(34, 50, DisplayName = "CiphertextSize(34) == 50")]
        [DataRow(63, 79, DisplayName = "CiphertextSize(63) == 79")]
        [DataRow(64, 80, DisplayName = "CiphertextSize(64) == 80")]
        [DataRow(65, 89, DisplayName = "CiphertextSize(65) == 89")]
        public void TestCiphertextSize(int cleartextSize, int expectedCiphertextSize)
        {
            // Act
            long result = _contentCryptor.Object.CiphertextSize(cleartextSize);

            // Assert
            Assert.AreEqual(expectedCiphertextSize, result);
        }

        [DataTestMethod]
        [DataRow(-1, DisplayName = "CiphertextSize(-1) throws")]
        public void TestCiphertextSizeWithInvalidCleartextSize(int invalidCleartextSize)
        {
            // Act & Assert
            Assert.ThrowsException<ArgumentException>(() =>
                _contentCryptor.Object.CiphertextSize(invalidCleartextSize));
        }
    }
}