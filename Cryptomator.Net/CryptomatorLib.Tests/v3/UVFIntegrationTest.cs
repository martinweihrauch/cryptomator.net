using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Common;
using CryptomatorLib.Api;
using CryptomatorLib.V3;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptomatorLib.Tests.V3
{
    [TestClass]
    public class UVFIntegrationTest
    {
        private static RandomNumberGenerator CSPRNG;
        private static UVFMasterkey masterkey;
        private static ICryptor cryptor;

        [ClassInitialize]
        public static void SetUp(TestContext context)
        {
            CSPRNG = RandomNumberGenerator.Create();

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
            cryptor = CryptorProvider.ForScheme(CryptorProvider.Scheme.UVF_DRAFT).Provide(masterkey, CSPRNG);
        }

        [ClassCleanup]
        public static void TearDown()
        {
            CSPRNG.Dispose();
        }

        [TestMethod]
        [DisplayName("Root dir id must be deterministic")]
        public void TestRootDirId()
        {
            byte[] rootDirId = masterkey.GetRootDirId();
            Assert.AreEqual("5WEGzwKkAHPwVSjT2Brr3P3zLz7oMiNpMn/qBvht7eM=", Convert.ToBase64String(rootDirId));
        }

        [TestMethod]
        [DisplayName("Root dir hash must be deterministic")]
        public void TestRootDirHash()
        {
            byte[] rootDirId = Convert.FromBase64String("5WEGzwKkAHPwVSjT2Brr3P3zLz7oMiNpMn/qBvht7eM=");
            string dirHash = Convert.ToBase64String(rootDirId).Replace('/', '_').Replace('+', '-').TrimEnd('=');
            Assert.AreEqual("RZK7ZH7KBXULNEKBMGX3CU42PGUIAIX4", dirHash);
        }

        [TestMethod]
        [DisplayName("Encrypt dir.uvf for root directory")]
        public void TestRootDirUvfEncryption()
        {
            var rootDirMetadata = cryptor.DirectoryContentCryptor().RootDirectoryMetadata();
            byte[] result = cryptor.DirectoryContentCryptor().EncryptDirectoryMetadata(rootDirMetadata);

            // Check UVF0 magic bytes
            byte[] magicBytes = new byte[4];
            Array.Copy(result, magicBytes, 4);
            CollectionAssert.AreEqual(new byte[] { 0x75, 0x76, 0x66, 0x00 }, magicBytes, "Expected to begin with UVF0 magic bytes");

            // Check seed 
            byte[] seedBytes = new byte[4];
            Array.Copy(result, 4, seedBytes, 0, 4);
            byte[] expectedSeed = Convert.FromBase64String("HDm38i==").AsSpan().Slice(0, 4).ToArray();
            CollectionAssert.AreEqual(expectedSeed, seedBytes, "Expected seed to be initial seed");
        }

        [TestMethod]
        [DisplayName("Decrypt dir.uvf for root directory")]
        public void TestRootDirUvfDecryption()
        {
            byte[] input = Convert.FromBase64String("dXZmABw5t/Ievp74RjIgGHn4+/Zt32dmqmYhmHiPNQ5Q2z+WYb4z8NbnynTgMWlGBCc65bTqSt4Pqhj9EGhrn8KVbQqzBVWcZkLVr4tntfvgZoVJYkeD5w9mJMwRlQJwqiC0uR+Lk2aBT2cfdPT92e/6+t7nlvoYtoahMtowCqY=");
            DirectoryMetadata result = cryptor.DirectoryContentCryptor().DecryptDirectoryMetadata(input);

            Assert.IsInstanceOfType(result, typeof(DirectoryMetadataImpl));
            DirectoryMetadataImpl metadata = (DirectoryMetadataImpl)result;

            CollectionAssert.AreEqual(masterkey.GetRootDirId(), metadata.DirId());
            Assert.AreEqual(masterkey.GetFirstRevision(), metadata.SeedId());
        }

        [TestMethod]
        [DisplayName("Encrypt file containing 'Hello, World!'")]
        public void TestContentEncryption()
        {
            byte[] cleartext = Encoding.UTF8.GetBytes("Hello, World!");
            byte[] result = EncryptFile(cleartext, cryptor);

            // Check UVF0 magic bytes
            byte[] magicBytes = new byte[4];
            Array.Copy(result, magicBytes, 4);
            CollectionAssert.AreEqual(new byte[] { 0x75, 0x76, 0x66, 0x00 }, magicBytes, "Expected to begin with UVF0 magic bytes");

            // Check seed 
            byte[] seedBytes = new byte[4];
            Array.Copy(result, 4, seedBytes, 0, 4);
            byte[] expectedSeed = Convert.FromBase64String("QBsJFo==").AsSpan().Slice(0, 4).ToArray();
            CollectionAssert.AreEqual(expectedSeed, seedBytes, "Expected seed to be latest seed");
        }

        [TestMethod]
        [DisplayName("Decrypt file containing 'Hello, World!'")]
        public void TestContentDecryption()
        {
            byte[] input = Convert.FromBase64String("dXZmAEAbCRZxhI5sPsMiMlAQpwXzsOw13pBVX/yHydeHoOlHBS9d+wVpmRvzUKx5HQUmtGR4avjDownMNOS4sBX8G0SVc5dIADKnGUOwgF20kkc/EpGzrrgkS3C9lZoRPPOj3dm2ONfy3UkT1Q==");
            byte[] result = DecryptFile(input, cryptor);

            Assert.AreEqual(13, result.Length);
            Assert.AreEqual("Hello, World!", Encoding.UTF8.GetString(result));
        }

        [TestMethod]
        [DisplayName("Create reference directory structure")]
        public void TestCreateReferenceDirStructure()
        {
            string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(tempPath);

            try
            {
                var dirContentCryptor = cryptor.DirectoryContentCryptor();

                // ROOT
                var rootDirMetadata = cryptor.DirectoryContentCryptor().RootDirectoryMetadata();
                string rootDirPath = dirContentCryptor.DirPath(rootDirMetadata);
                string rootDirUvfFilePath = Path.Combine(rootDirPath, "dir.uvf");
                byte[] rootDirUvfFileContents = dirContentCryptor.EncryptDirectoryMetadata(rootDirMetadata);

                Directory.CreateDirectory(Path.Combine(tempPath, rootDirPath));
                File.WriteAllBytes(Path.Combine(tempPath, rootDirUvfFilePath), rootDirUvfFileContents);
                var filesWithinRootDir = dirContentCryptor.FileNameEncryptor(rootDirMetadata);

                // ROOT/foo.txt
                string fooFileName = filesWithinRootDir.Encrypt("foo.txt");
                string fooFilePath = Path.Combine(rootDirPath, fooFileName);
                byte[] fooFileContents = EncryptFile(Encoding.UTF8.GetBytes("Hello Foo"), cryptor);
                File.WriteAllBytes(Path.Combine(tempPath, fooFilePath), fooFileContents);

                // ROOT/subdir
                var subDirMetadata = dirContentCryptor.NewDirectoryMetadata();
                string subDirName = filesWithinRootDir.Encrypt("subdir");
                string subDirUvfFilePath1 = Path.Combine(rootDirPath, subDirName, "dir.uvf");
                byte[] subDirUvfFileContents1 = dirContentCryptor.EncryptDirectoryMetadata(subDirMetadata);

                Directory.CreateDirectory(Path.Combine(tempPath, rootDirPath, subDirName));
                File.WriteAllBytes(Path.Combine(tempPath, subDirUvfFilePath1), subDirUvfFileContents1);

                string subDirPath = dirContentCryptor.DirPath(subDirMetadata);
                string subDirUvfFilePath2 = Path.Combine(subDirPath, "dir.uvf");
                byte[] subDirUvfFileContents2 = dirContentCryptor.EncryptDirectoryMetadata(subDirMetadata);

                Directory.CreateDirectory(Path.Combine(tempPath, subDirPath));
                File.WriteAllBytes(Path.Combine(tempPath, subDirUvfFilePath2), subDirUvfFileContents2);
                var filesWithinSubDir = dirContentCryptor.FileNameEncryptor(subDirMetadata);

                // ROOT/subdir/bar.txt
                string barFileName = filesWithinSubDir.Encrypt("bar.txt");
                string barFilePath = Path.Combine(subDirPath, barFileName);
                byte[] barFileContents = EncryptFile(Encoding.UTF8.GetBytes("Hello Bar"), cryptor);
                File.WriteAllBytes(Path.Combine(tempPath, barFilePath), barFileContents);

                // Verify directory structure was created
                Assert.IsTrue(Directory.Exists(Path.Combine(tempPath, rootDirPath)));
                Assert.IsTrue(File.Exists(Path.Combine(tempPath, rootDirUvfFilePath)));
                Assert.IsTrue(File.Exists(Path.Combine(tempPath, fooFilePath)));
                Assert.IsTrue(Directory.Exists(Path.Combine(tempPath, rootDirPath, subDirName)));
                Assert.IsTrue(File.Exists(Path.Combine(tempPath, subDirUvfFilePath1)));
                Assert.IsTrue(Directory.Exists(Path.Combine(tempPath, subDirPath)));
                Assert.IsTrue(File.Exists(Path.Combine(tempPath, subDirUvfFilePath2)));
                Assert.IsTrue(File.Exists(Path.Combine(tempPath, barFilePath)));
            }
            finally
            {
                // Clean up
                try
                {
                    Directory.Delete(tempPath, true);
                }
                catch
                {
                    // Ignore cleanup errors
                }
            }
        }

        private static byte[] EncryptFile(byte[] cleartext, ICryptor cryptor)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                // Create a stream adapter for the output
                var outputChannel = new Common.StreamTestByteChannel(ms);

                using (var encryptingChannel = new Common.EncryptingWritableByteChannel(outputChannel, cryptor))
                {
                    encryptingChannel.Write(cleartext, 0, cleartext.Length);
                }
                return ms.ToArray();
            }
        }

        private static byte[] DecryptFile(byte[] ciphertext, ICryptor cryptor)
        {
            using (MemoryStream inputStream = new MemoryStream(ciphertext))
            using (MemoryStream outputStream = new MemoryStream())
            {
                // Calculate cleartext size
                long cleartextSize = cryptor.FileContentCryptor().CleartextSize(ciphertext.Length) - cryptor.FileHeaderCryptor().HeaderSize();

                // Create a stream adapter for the input
                var inputChannel = new Common.StreamTestByteChannel(inputStream);

                using (var decryptingChannel = new Common.DecryptingReadableByteChannel(inputChannel, cryptor))
                {
                    byte[] buffer = new byte[cleartextSize];
                    int read = decryptingChannel.Read(buffer, 0, buffer.Length);
                    Assert.AreEqual(13, read);

                    outputStream.Write(buffer, 0, read);
                }

                return outputStream.ToArray();
            }
        }
    }
}