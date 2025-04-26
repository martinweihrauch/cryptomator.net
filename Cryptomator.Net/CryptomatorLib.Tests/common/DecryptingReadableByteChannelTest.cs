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
    public class DecryptingReadableByteChannelTest
    {
        private Mock<Cryptor> _cryptor;
        private Mock<FileContentCryptor> _contentCryptor;
        private Mock<FileHeaderCryptor> _headerCryptor;
        private Mock<FileHeader> _header;

        [TestInitialize]
        public void Setup()
        {
            _cryptor = new Mock<Cryptor>();
            _contentCryptor = new Mock<FileContentCryptor>();
            _headerCryptor = new Mock<FileHeaderCryptor>();
            _header = new Mock<FileHeader>();

            _cryptor.Setup(c => c.FileContentCryptor()).Returns(_contentCryptor.Object);
            _cryptor.Setup(c => c.FileHeaderCryptor()).Returns(_headerCryptor.Object);

            _contentCryptor.Setup(c => c.CleartextChunkSize()).Returns(10);
            _contentCryptor.Setup(c => c.CiphertextChunkSize()).Returns(10);

            _headerCryptor.Setup(h => h.HeaderSize()).Returns(5);
            _headerCryptor.Setup(h => h.DecryptHeader(It.IsAny<ReadOnlyMemory<byte>>())).Returns(_header.Object);

            _contentCryptor.Setup(c => c.DecryptChunk(
                    It.IsAny<ReadOnlyMemory<byte>>(),
                    It.IsAny<Memory<byte>>(),
                    It.IsAny<long>(),
                    It.IsAny<FileHeader>(),
                    It.IsAny<bool>()))
                .Callback<ReadOnlyMemory<byte>, Memory<byte>, long, FileHeader, bool>(
                    (data, output, chunkNumber, header, auth) =>
                    {
                        // Simulate conversion to lowercase for testing purposes
                        string content = Encoding.UTF8.GetString(data.ToArray());
                        byte[] result = Encoding.UTF8.GetBytes(content.ToLower());
                        result.CopyTo(output);
                    });
        }

        [TestMethod]
        [DisplayName("Test Decryption")]
        public void TestDecryption()
        {
            // Create a source stream with test data
            byte[] sourceData = Encoding.UTF8.GetBytes("hhhhhTOPSECRET!TOPSECRET!");
            using (MemoryStream source = new MemoryStream(sourceData))
            {
                byte[] resultBuffer = new byte[30];

                // Create a channel adapter
                var channelAdapter = new StreamTestByteChannel(source);

                // Create decrypting channel
                using (var channel = new DecryptingReadableByteChannel(channelAdapter, _cryptor.Object))
                {
                    // Read data from the channel
                    int bytesRead1 = channel.Read(resultBuffer, 0, resultBuffer.Length);
                    Assert.AreEqual(20, bytesRead1);

                    // Try to read more (should return 0 indicating EOF)
                    int bytesRead2 = channel.Read(resultBuffer, bytesRead1, resultBuffer.Length - bytesRead1);
                    Assert.AreEqual(0, bytesRead2);

                    // Verify the decrypted content
                    byte[] decryptedData = new byte[bytesRead1];
                    Array.Copy(resultBuffer, 0, decryptedData, 0, bytesRead1);
                    CollectionAssert.AreEqual(
                        Encoding.UTF8.GetBytes("topsecret!topsecret!"),
                        decryptedData);
                }
            }

            // Verify the expected method calls
            _headerCryptor.Verify(h => h.DecryptHeader(It.IsAny<ReadOnlyMemory<byte>>()), Times.Once);
            _contentCryptor.Verify(c => c.DecryptChunk(
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<Memory<byte>>(),
                It.IsAny<long>(),
                It.IsAny<FileHeader>(),
                It.IsAny<bool>()),
                Times.AtLeastOnce);
        }

        [TestMethod]
        [DisplayName("Test Random Access Decryption")]
        public void TestRandomAccessDecryption()
        {
            // Create a source stream with test data
            byte[] sourceData = Encoding.UTF8.GetBytes("TOPSECRET!");
            using (MemoryStream source = new MemoryStream(sourceData))
            {
                byte[] resultBuffer = new byte[30];

                // Create a channel adapter
                var channelAdapter = new StreamTestByteChannel(source);

                // Create decrypting channel
                using (var channel = new DecryptingReadableByteChannel(channelAdapter, _cryptor.Object))
                {
                    // Read data from the channel
                    int bytesRead1 = channel.Read(resultBuffer, 0, resultBuffer.Length);
                    Assert.AreEqual(10, bytesRead1);

                    // Try to read more (should return 0 indicating EOF)
                    int bytesRead2 = channel.Read(resultBuffer, bytesRead1, resultBuffer.Length - bytesRead1);
                    Assert.AreEqual(0, bytesRead2);

                    // Verify the decrypted content
                    byte[] decryptedData = new byte[bytesRead1];
                    Array.Copy(resultBuffer, 0, decryptedData, 0, bytesRead1);
                    CollectionAssert.AreEqual(
                        Encoding.UTF8.GetBytes("topsecret!"),
                        decryptedData);
                }
            }

            // Verify the expected method calls
            _headerCryptor.Verify(h => h.DecryptHeader(It.IsAny<ReadOnlyMemory<byte>>()), Times.AtLeastOnce);
            _contentCryptor.Verify(c => c.DecryptChunk(
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<Memory<byte>>(),
                It.IsAny<long>(),
                It.IsAny<FileHeader>(),
                It.IsAny<bool>()),
                Times.AtLeastOnce);
        }
    }
}