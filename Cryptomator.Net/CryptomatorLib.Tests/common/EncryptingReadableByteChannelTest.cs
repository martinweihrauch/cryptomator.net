using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using Moq;
using System;
using System.IO;
using System.Text;

namespace CryptomatorLib.Tests.Common
{
    [TestClass]
    public class EncryptingReadableByteChannelTest
    {
        private byte[] _dstFile;
        private SeekableByteChannelMock _srcFileChannel;
        private Mock<Cryptor> _cryptor;
        private Mock<FileContentCryptor> _contentCryptor;
        private Mock<FileHeaderCryptor> _headerCryptor;
        private Mock<FileHeader> _header;

        [TestInitialize]
        public void Setup()
        {
            _dstFile = new byte[100];
            _srcFileChannel = new SeekableByteChannelMock(_dstFile);
            _cryptor = new Mock<Cryptor>();
            _contentCryptor = new Mock<FileContentCryptor>();
            _headerCryptor = new Mock<FileHeaderCryptor>();
            _header = new Mock<FileHeader>();

            _cryptor.Setup(c => c.GetFileContentCryptor()).Returns(_contentCryptor.Object);
            _cryptor.Setup(c => c.GetFileHeaderCryptor()).Returns(_headerCryptor.Object);

            _contentCryptor.Setup(c => c.GetCleartextChunkSize()).Returns(10);

            _headerCryptor.Setup(h => h.Create()).Returns(_header.Object);
            _headerCryptor.Setup(h => h.EncryptHeader(_header.Object)).Returns(Encoding.UTF8.GetBytes("hhhhh"));

            _contentCryptor.Setup(c => c.EncryptChunk(
                    It.IsAny<byte[]>(),
                    It.IsAny<long>(),
                    It.IsAny<FileHeader>()))
                .Returns<byte[], long, FileHeader>((data, chunkNumber, header) =>
                {
                    // Simulate conversion to uppercase for testing purposes
                    string content = Encoding.UTF8.GetString(data);
                    return Encoding.UTF8.GetBytes(content.ToUpper());
                });
        }

        [TestMethod]
        [DisplayName("Test Encryption Of Empty Cleartext")]
        public void TestEncryptionOfEmptyCleartext()
        {
            // Create a source stream with no data
            byte[] sourceData = new byte[0];
            using (MemoryStream source = new MemoryStream(sourceData))
            {
                byte[] resultBuffer = new byte[10];

                // Create encrypting channel
                using (var channel = new EncryptingReadableByteChannel(source, _cryptor.Object))
                {
                    // Read data from the channel - should only get the header
                    int bytesRead1 = channel.Read(resultBuffer, 0, resultBuffer.Length);
                    Assert.AreEqual(5, bytesRead1);

                    // Try to read more (should return -1 indicating EOF)
                    int bytesRead2 = channel.Read(resultBuffer, bytesRead1, resultBuffer.Length - bytesRead1);
                    Assert.AreEqual(-1, bytesRead2);

                    // Verify the encrypted content (should just be the header)
                    byte[] encryptedData = new byte[bytesRead1];
                    Array.Copy(resultBuffer, 0, encryptedData, 0, bytesRead1);
                    CollectionAssert.AreEqual(
                        Encoding.UTF8.GetBytes("hhhhh"),
                        encryptedData);
                }
            }

            // Verify encrypt chunk was never called (no content to encrypt)
            _contentCryptor.Verify(c => c.EncryptChunk(
                It.IsAny<byte[]>(),
                It.IsAny<long>(),
                It.IsAny<FileHeader>()),
                Times.Never);
        }

        [TestMethod]
        [DisplayName("Test Encryption Of Cleartext")]
        public void TestEncryptionOfCleartext()
        {
            // Create a source stream with test data
            byte[] sourceData = Encoding.UTF8.GetBytes("hello world 1 hello world 2");
            using (MemoryStream source = new MemoryStream(sourceData))
            {
                byte[] resultBuffer = new byte[50];

                // Create encrypting channel
                using (var channel = new EncryptingReadableByteChannel(source, _cryptor.Object))
                {
                    // Read data from the channel
                    int bytesRead1 = channel.Read(resultBuffer, 0, resultBuffer.Length);
                    Assert.AreEqual(32, bytesRead1);

                    // Try to read more (should return -1 indicating EOF)
                    int bytesRead2 = channel.Read(resultBuffer, bytesRead1, resultBuffer.Length - bytesRead1);
                    Assert.AreEqual(-1, bytesRead2);

                    // Verify the encrypted content
                    byte[] encryptedData = new byte[bytesRead1];
                    Array.Copy(resultBuffer, 0, encryptedData, 0, bytesRead1);
                    CollectionAssert.AreEqual(
                        Encoding.UTF8.GetBytes("hhhhhHELLO WORLD 1 HELLO WORLD 2"),
                        encryptedData);
                }
            }

            // Verify the expected calls were made
            _contentCryptor.Verify(c => c.EncryptChunk(
                It.IsAny<byte[]>(),
                It.Is<long>(chunkNumber => chunkNumber == 0),
                It.IsAny<FileHeader>()),
                Times.Once);

            _contentCryptor.Verify(c => c.EncryptChunk(
                It.IsAny<byte[]>(),
                It.Is<long>(chunkNumber => chunkNumber == 1),
                It.IsAny<FileHeader>()),
                Times.Once);
        }
    }
}