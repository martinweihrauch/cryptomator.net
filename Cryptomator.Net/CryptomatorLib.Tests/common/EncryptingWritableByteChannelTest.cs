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
    public class EncryptingWritableByteChannelTest
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
            _contentCryptor.Setup(c => c.CiphertextChunkSize()).Returns(20);

            _headerCryptor.Setup(h => h.Create()).Returns(_header.Object);
            _headerCryptor.Setup(h => h.EncryptHeader(_header.Object)).Returns(new Memory<byte>(Encoding.UTF8.GetBytes("hhhhh")));

            _contentCryptor.Setup(c => c.EncryptChunk(
                    It.IsAny<ReadOnlyMemory<byte>>(),
                    It.IsAny<long>(),
                    It.IsAny<FileHeader>()))
                .Returns<ReadOnlyMemory<byte>, long, FileHeader>((data, chunkNumber, header) =>
                {
                    // Simulate conversion to uppercase and wrapping with < > for testing
                    string content = Encoding.UTF8.GetString(data.ToArray());
                    return new Memory<byte>(Encoding.UTF8.GetBytes("<" + content.ToUpper() + ">"));
                });
        }

        [TestMethod]
        [DisplayName("Test Encryption")]
        public void TestEncryption()
        {
            using var dstFile = new MemoryStream(100);
            var testChannel = new StreamTestByteChannel(dstFile);
            
            using (var channel = new EncryptingWritableByteChannel(testChannel, _cryptor.Object))
            {
                byte[] data1 = Encoding.UTF8.GetBytes("hello world 1");
                channel.Write(data1, 0, data1.Length);

                byte[] data2 = Encoding.UTF8.GetBytes("hello world 2");
                channel.Write(data2, 0, data2.Length);
            }

            // Reset stream position to beginning for reading
            dstFile.Position = 0;

            // Read the encrypted content
            byte[] resultBuffer = new byte[100];
            int bytesRead = dstFile.Read(resultBuffer, 0, resultBuffer.Length);
            string encrypted = Encoding.UTF8.GetString(resultBuffer, 0, bytesRead);

            // Verify the expected encrypted content
            Assert.AreEqual("hhhhh<HELLO WORL><D 1HELLO W><ORLD 2>", encrypted);
        }

        [TestMethod]
        [DisplayName("Test Encryption Of Empty File")]
        public void TestEncryptionOfEmptyFile()
        {
            using var dstFile = new MemoryStream(100);
            var testChannel = new StreamTestByteChannel(dstFile);
            
            using (var channel = new EncryptingWritableByteChannel(testChannel, _cryptor.Object))
            {
                // Empty, so write nothing
            }

            // Reset stream position to beginning for reading
            dstFile.Position = 0;

            // Read the encrypted content
            byte[] resultBuffer = new byte[100];
            int bytesRead = dstFile.Read(resultBuffer, 0, resultBuffer.Length);
            string encrypted = Encoding.UTF8.GetString(resultBuffer, 0, bytesRead);

            // Verify the expected encrypted content (header + empty chunk)
            Assert.AreEqual("hhhhh<>", encrypted);
        }
    }
}