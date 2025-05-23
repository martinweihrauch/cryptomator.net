using Microsoft.VisualStudio.TestTools.UnitTesting;
using UvfLib.Common;
using UvfLib.Api;
using UvfLib.V3;
using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Diagnostics;
using UvfLib.Tests.Common;

namespace UvfLib.Tests.V3
{
    [TestClass]
    public class DirectoryContentCryptorImplTest
    {
        private static RandomNumberGenerator CSPRNG;
        private static UVFMasterkey masterkey;
        private static DirectoryContentCryptorImpl dirCryptor;

        [ClassInitialize]
        public static void SetUp(TestContext context)
        {
            // Use deterministic RNG for tests
            CSPRNG = SecureRandomMock.NULL_RANDOM;

            // Setup masterkey with the same test data as in Java tests
            string json = "{\n" +
                "    \"fileFormat\": \"AES-256-GCM-32k\",\n" +
                "    \"nameFormat\": \"AES-SIV-512-B64URL\",\n" +
                "    \"seeds\": {\n" +
                "        \"HDm38g\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\",\n" +
                "        \"gBryKw\": \"PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0\",\n" +
                "        \"QBsJFg\": \"Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y\"\n" +
                "    },\n" +
                "    \"initialSeed\": \"HDm38i\",\n" +
                "    \"latestSeed\": \"QBsJFo\",\n" +
                "    \"kdf\": \"HKDF-SHA512\",\n" +
                "    \"kdfSalt\": \"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\n" +
                "    \"org.example.customfield\": 42\n" +
                "}";

            masterkey = UVFMasterkey.FromDecryptedPayload(json);
            dirCryptor = (DirectoryContentCryptorImpl)CryptorProvider.ForScheme(CryptorProvider.Scheme.UVF_DRAFT).Provide(masterkey, CSPRNG).DirectoryContentCryptor();
        }

        [ClassCleanup]
        public static void TearDown()
        {
            CSPRNG.Dispose();
        }

        [TestMethod]
        [DisplayName("Encrypt and decrypt dir.uvf files")]
        public void EncryptAndDecryptDirectoryMetadata()
        {
            DirectoryMetadataImpl origMetadata = (DirectoryMetadataImpl)dirCryptor.NewDirectoryMetadata();

            byte[] encryptedMetadata = dirCryptor.EncryptDirectoryMetadata(origMetadata);
            DirectoryMetadataImpl decryptedMetadata = (DirectoryMetadataImpl)dirCryptor.DecryptDirectoryMetadata(encryptedMetadata);

            Assert.AreEqual(origMetadata.SeedId(), decryptedMetadata.SeedId());
            CollectionAssert.AreEqual(origMetadata.DirId(), decryptedMetadata.DirId());
        }

        [TestMethod]
        [DisplayName("Encrypt WELCOME.rtf in root dir")]
        public void TestEncryptReadme()
        {
            DirectoryMetadata rootDirMetadata = dirCryptor.RootDirectoryMetadata();
            IDirectoryContentCryptor.Encrypting enc = dirCryptor.FileNameEncryptor(rootDirMetadata);

            string ciphertext = enc.Encrypt("WELCOME.rtf");

            Assert.AreEqual("Dx1binBPsg_KNby6KFD_2k3vZHPgo39rg4ks.uvf", ciphertext);
        }

        [TestMethod]
        [DisplayName("Decrypt WELCOME.rtf in root dir")]
        public void TestDecryptReadme()
        {
            DirectoryMetadata rootDirMetadata = dirCryptor.RootDirectoryMetadata();
            IDirectoryContentCryptor.Decrypting dec = dirCryptor.FileNameDecryptor(rootDirMetadata);

            string plaintext = dec.Decrypt("Dx1binBPsg_KNby6KFD_2k3vZHPgo39rg4ks.uvf");

            Assert.AreEqual("WELCOME.rtf", plaintext);
        }

        [TestMethod]
        [DisplayName("Get root dir path")]
        public void TestRootDirPath()
        {
            DirectoryMetadata rootDirMetadata = dirCryptor.RootDirectoryMetadata();

            string path = dirCryptor.DirPath(rootDirMetadata);

            Assert.AreEqual("d/RZ/K7ZH7KBXULNEKBMGX3CU42PGUIAIX4", path);
        }

        [TestClass]
        [TestCategory("WithDirectoryMetadata")]
        public class WithDirectoryMetadata
        {
            private DirectoryMetadataImpl dirUvf;
            private IDirectoryContentCryptor.Encrypting enc;
            private IDirectoryContentCryptor.Decrypting dec;

            [TestInitialize]
            public void Setup()
            {
                // Add null checks for debugging
                if (DirectoryContentCryptorImplTest.masterkey == null)
                {
                    throw new InvalidOperationException("Outer class masterkey is null in nested Setup");
                }
                if (DirectoryContentCryptorImplTest.dirCryptor == null)
                {
                    throw new InvalidOperationException("Outer class dirCryptor is null in nested Setup");
                }

                // Create an empty directory ID as in Java test
                dirUvf = new DirectoryMetadataImpl(DirectoryContentCryptorImplTest.masterkey.GetCurrentRevision(), new byte[32]);
                enc = DirectoryContentCryptorImplTest.dirCryptor.FileNameEncryptor(dirUvf);
                dec = DirectoryContentCryptorImplTest.dirCryptor.FileNameDecryptor(dirUvf);
            }

            [DataTestMethod]
            [DataRow("file1.txt", "NIWamUJBS3u619f3yKOWlT2q_raURsHXhg==.uvf")]
            [DataRow("file2.txt", "_EWTVc9qooJQyk-P9pwQkvSu9mFb0UWNeg==.uvf")]
            [DataRow("file3.txt", "dunZsv8VRuh81R-u6pioPx2DWeQAU0nLfw==.uvf")]
            [DataRow("file4.txt", "2-clI661p9TBSzC2IJjvBF3ehaKas5Vqxg==.uvf")]
            [DisplayName("Encrypt multiple file names")]
            public void TestBulkEncryption(string plaintext, string expectedCiphertext)
            {
                string actualCiphertext = enc.Encrypt(plaintext);
                Assert.AreEqual(expectedCiphertext, actualCiphertext);
            }

            [DataTestMethod]
            [DataRow("file1.txt", "NIWamUJBS3u619f3yKOWlT2q_raURsHXhg==.uvf")]
            [DataRow("file2.txt", "_EWTVc9qooJQyk-P9pwQkvSu9mFb0UWNeg==.uvf")]
            [DataRow("file3.txt", "dunZsv8VRuh81R-u6pioPx2DWeQAU0nLfw==.uvf")]
            [DataRow("file4.txt", "2-clI661p9TBSzC2IJjvBF3ehaKas5Vqxg==.uvf")]
            [DisplayName("Decrypt multiple file names")]
            public void TestBulkDecryption(string expectedPlaintext, string ciphertext)
            {
                string actualPlaintext = dec.Decrypt(ciphertext);
                Assert.AreEqual(expectedPlaintext, actualPlaintext);
            }

            [TestMethod]
            [DisplayName("Decrypt file with invalid extension")]
            public void TestDecryptMalformed1()
            {
                Assert.ThrowsException<ArgumentException>(() =>
                {
                    dec.Decrypt("NIWamUJBS3u619f3yKOWlT2q_raURsHXhg==.INVALID");
                });
            }

            [TestMethod]
            [DisplayName("Decrypt file with unauthentic ciphertext")]
            public void TestDecryptMalformed2()
            {
                Assert.ThrowsException<AuthenticationFailedException>(() =>
                {
                    dec.Decrypt("INVALIDamUJBS3u619f3yKOWlT2q_raURsHXhg==.uvf");
                });
            }

            [TestMethod]
            [DisplayName("Decrypt file with incorrect seed")]
            public void TestDecryptMalformed3()
            {
                DirectoryMetadataImpl differentRevision = new DirectoryMetadataImpl(
                    DirectoryContentCryptorImplTest.masterkey.GetFirstRevision(),
                    new byte[32]);

                IDirectoryContentCryptor.Decrypting differentRevisionDec =
                    DirectoryContentCryptorImplTest.dirCryptor.FileNameDecryptor(differentRevision);

                Assert.ThrowsException<AuthenticationFailedException>(() =>
                {
                    differentRevisionDec.Decrypt("NIWamUJBS3u619f3yKOWlT2q_raURsHXhg==.uvf");
                });
            }

            [TestMethod]
            [DisplayName("Decrypt file with incorrect dirId")]
            public void TestDecryptMalformed4()
            {
                // Create a different, but valid, 32-byte directory ID
                byte[] differentDirId = new byte[32];
                Array.Fill(differentDirId, (byte)0xFF); // Fill with a different value

                DirectoryMetadataImpl differentDirIdMetadata = new DirectoryMetadataImpl(
                    DirectoryContentCryptorImplTest.masterkey.GetCurrentRevision(), // Use current revision like in setup
                    differentDirId);

                IDirectoryContentCryptor.Decrypting differentDirIdDec =
                    DirectoryContentCryptorImplTest.dirCryptor.FileNameDecryptor(differentDirIdMetadata);

                Assert.ThrowsException<AuthenticationFailedException>(() =>
                {
                    differentDirIdDec.Decrypt("NIWamUJBS3u619f3yKOWlT2q_raURsHXhg==.uvf");
                });
            }
        }
    }
}