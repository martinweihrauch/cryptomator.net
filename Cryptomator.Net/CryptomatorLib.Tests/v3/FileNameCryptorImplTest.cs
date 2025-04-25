using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using CryptomatorLib.Tests.Common;
using CryptomatorLib.V3;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CryptomatorLib.Tests.V3
{
    [TestClass]
    public class FileNameCryptorImplTest
    {
        // Define test data for masterkey creation - same as in Java tests for consistency
        private static readonly Dictionary<int, byte[]> SEEDS = new Dictionary<int, byte[]>
        {
            { -1540072521, Convert.FromBase64String("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU=".Replace('-', '+').Replace('_', '/')) }
        };
        private static readonly byte[] KDF_SALT = Convert.FromBase64String("HE4OP-2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY=".Replace('-', '+').Replace('_', '/'));
        private static readonly UVFMasterkey MASTERKEY = new UVFMasterkeyImpl(SEEDS, KDF_SALT, -1540072521, -1540072521);

        private FileNameCryptorImpl _filenameCryptor;
        private readonly RandomNumberGenerator _random = SecureRandomMock.NULL_RANDOM;

        [TestInitialize]
        public void Setup()
        {
            // Initialize the filename cryptor
            _filenameCryptor = new FileNameCryptorImpl(MASTERKEY, _random);
        }

        [TestMethod]
        [DisplayName("Test Deterministic Encryption Of Filenames")]
        public void TestDeterministicEncryptionOfFilenames()
        {
            // Test with a sample filename
            string origName = "test-file-name.txt";

            string encrypted1 = _filenameCryptor.EncryptFilename(origName);
            string encrypted2 = _filenameCryptor.EncryptFilename(origName);
            string decrypted = _filenameCryptor.DecryptFilename(encrypted1);

            Assert.AreEqual(encrypted1, encrypted2, "Encryption should be deterministic");
            Assert.AreEqual(origName, decrypted, "Decryption should restore the original filename");
        }

        [TestMethod]
        [DisplayName("Test Encrypt And Decrypt Multiple Filenames")]
        public void TestEncryptAndDecryptMultipleFilenames()
        {
            // Test with multiple filenames
            string[] origNames = {
                "document.txt",
                "image.jpg",
                "archive.zip",
                "script.cs",
                "longfilename-with-hyphens.txt",
                "fileWith Spaces.pdf"
            };

            foreach (string origName in origNames)
            {
                string encrypted = _filenameCryptor.EncryptFilename(origName);
                string decrypted = _filenameCryptor.DecryptFilename(encrypted);
                Assert.AreEqual(origName, decrypted, $"Decryption failed for {origName}");
            }
        }

        [TestMethod]
        [DisplayName("Test Encryption Of Filenames With Custom Prefix")]
        public void TestEncryptionOfFilenamesWithCustomPrefix()
        {
            // Test with a custom prefix
            string origName = "test-file.txt";
            string prefix = "PREFIX_";

            string encrypted = _filenameCryptor.EncryptFilename(origName, prefix);
            string decrypted = _filenameCryptor.DecryptFilename(encrypted.Substring(prefix.Length));

            Assert.IsTrue(encrypted.StartsWith(prefix), "Encrypted filename should start with prefix");
            Assert.AreEqual(origName, decrypted, "Decryption should restore the original filename");
        }

        [TestMethod]
        [DisplayName("Test Encrypt And Decrypt Directory IDs")]
        public void TestEncryptAndDecryptDirectoryIds()
        {
            // Test directory ID encryption/decryption
            string dirId = "directory-id-123";

            string encryptedDirId = _filenameCryptor.EncryptDirectoryId(dirId);
            string decryptedDirId = _filenameCryptor.DecryptDirectoryId(encryptedDirId);

            Assert.AreEqual(dirId, decryptedDirId, "Decryption should restore the original directory ID");
        }

        [TestMethod]
        [DisplayName("Test Decryption Of Malformed Filename")]
        public void TestDecryptionOfMalformedFilename()
        {
            // Test with an invalid ciphertext
            string invalidCiphertext = "not-valid-ciphertext";

            Assert.ThrowsException<InvalidCiphertextException>(() =>
                _filenameCryptor.DecryptFilename(invalidCiphertext));
        }

        [TestMethod]
        [DisplayName("Test Decryption Of Manipulated Filename")]
        public void TestDecryptionOfManipulatedFilename()
        {
            // Test with a tampered ciphertext
            string origName = "test-file.txt";
            string encrypted = _filenameCryptor.EncryptFilename(origName);

            // Manipulate the encrypted filename by changing a character
            char[] chars = encrypted.ToCharArray();
            if (chars.Length > 0)
            {
                chars[chars.Length - 1] = chars[chars.Length - 1] == 'A' ? 'B' : 'A';
            }
            string tamperedEncrypted = new string(chars);

            Assert.ThrowsException<AuthenticationFailedException>(() =>
                _filenameCryptor.DecryptFilename(tamperedEncrypted));
        }

        [TestMethod]
        [DisplayName("Test With Empty Filename")]
        public void TestWithEmptyFilename()
        {
            // Test with empty inputs
            Assert.ThrowsException<ArgumentException>(() => _filenameCryptor.EncryptFilename(""));
            Assert.ThrowsException<ArgumentException>(() => _filenameCryptor.DecryptFilename(""));
            Assert.ThrowsException<ArgumentException>(() => _filenameCryptor.EncryptDirectoryId(""));
            Assert.ThrowsException<ArgumentException>(() => _filenameCryptor.DecryptDirectoryId(""));
        }

        [TestMethod]
        [DisplayName("Test With Null Filename")]
        public void TestWithNullFilename()
        {
            // Test with null inputs
            Assert.ThrowsException<ArgumentException>(() => _filenameCryptor.EncryptFilename(null));
            Assert.ThrowsException<ArgumentException>(() => _filenameCryptor.DecryptFilename(null));
            Assert.ThrowsException<ArgumentException>(() => _filenameCryptor.EncryptDirectoryId(null));
            Assert.ThrowsException<ArgumentException>(() => _filenameCryptor.DecryptDirectoryId(null));
        }

        [TestMethod]
        [DisplayName("Test Unicode Filenames")]
        public void TestUnicodeFilenames()
        {
            // Test with Unicode characters
            string[] unicodeNames = {
                "文件名.txt",
                "ファイル名.txt",
                "파일 이름.txt",
                "имя файла.txt",
                "αρχείο.txt",
                "שם קובץ.txt"
            };

            foreach (string name in unicodeNames)
            {
                string encrypted = _filenameCryptor.EncryptFilename(name);
                string decrypted = _filenameCryptor.DecryptFilename(encrypted);
                Assert.AreEqual(name, decrypted, $"Decryption failed for Unicode filename {name}");
            }
        }
    }
}