using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using CryptomatorLib.Tests.Common.TestUtilities;
using Moq;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptomatorLib.Tests.Common
{
    [TestClass]
    public class MasterkeyFileAccessTest
    {
        private static readonly RandomNumberGenerator RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
        private static readonly byte[] DEFAULT_PEPPER = new byte[0];

        private PerpetualMasterkey _key;
        private MasterkeyFile _keyFile;
        private MasterkeyFileAccess _masterkeyFileAccess;

        [TestInitialize]
        public void Setup()
        {
            _key = new PerpetualMasterkey(new byte[64]);
            _keyFile = new MasterkeyFile();
            _masterkeyFileAccess = new MasterkeyFileAccess(DEFAULT_PEPPER, RANDOM_MOCK);

            _keyFile.Version = 3;
            _keyFile.ScryptSalt = new byte[8];
            _keyFile.ScryptCostParam = 2;
            _keyFile.ScryptBlockSize = 8;
            _keyFile.EncMasterKey = Convert.FromBase64String("mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==");
            _keyFile.MacMasterKey = Convert.FromBase64String("mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==");
            _keyFile.VersionMac = Convert.FromBase64String("iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=");
        }

        [TestMethod]
        [DisplayName("Test Change Passphrase With MasterkeyFile")]
        public void TestChangePassphraseWithMasterkeyFile()
        {
            MasterkeyFile changed1 = _masterkeyFileAccess.ChangePassphrase(_keyFile, "asd", "qwe");
            MasterkeyFile changed2 = _masterkeyFileAccess.ChangePassphrase(changed1, "qwe", "asd");

            CollectionAssert.AreNotEqual(_keyFile.EncMasterKey, changed1.EncMasterKey);
            CollectionAssert.AreEqual(_keyFile.EncMasterKey, changed2.EncMasterKey);
        }

        [TestMethod]
        [DisplayName("Test Read Alleged Vault Version")]
        public void TestReadAllegedVaultVersion()
        {
            byte[] content = Encoding.UTF8.GetBytes("{\"version\": 1337}");

            int version = MasterkeyFileAccess.ReadAllegedVaultVersion(content);

            Assert.AreEqual(1337, version);
        }

        [TestClass]
        public class WithSerializedKeyFile
        {
            private PerpetualMasterkey _key;
            private MasterkeyFileAccess _masterkeyFileAccess;
            private byte[] _serializedKeyFile;

            [TestInitialize]
            public void Setup()
            {
                _key = new PerpetualMasterkey(new byte[64]);
                _masterkeyFileAccess = new MasterkeyFileAccess(new byte[0], SecureRandomMock.NULL_RANDOM);

                using (MemoryStream out1 = new MemoryStream())
                {
                    _masterkeyFileAccess.Persist(_key, out1, "asd", 999, 2);
                    _serializedKeyFile = out1.ToArray();
                }
            }

            [TestMethod]
            [DisplayName("Test Change Passphrase With Raw Bytes")]
            public void TestChangePassphraseWithRawBytes()
            {
                byte[] changed = _masterkeyFileAccess.ChangePassphrase(_serializedKeyFile, "asd", "qwe");
                byte[] restored = _masterkeyFileAccess.ChangePassphrase(changed, "qwe", "asd");

                CollectionAssert.AreNotEqual(changed, _serializedKeyFile);
                CollectionAssert.AreEqual(_serializedKeyFile, restored);
            }

            [TestMethod]
            [DisplayName("Test Load")]
            public void TestLoad()
            {
                using (MemoryStream in1 = new MemoryStream(_serializedKeyFile))
                {
                    PerpetualMasterkey loaded = _masterkeyFileAccess.Load(in1, "asd");
                    CollectionAssert.AreEqual(_key.GetRaw(), loaded.GetRaw());
                }
            }

            [TestMethod]
            [DisplayName("Test Load Invalid Json")]
            public void TestLoadInvalid()
            {
                string content = "{\"foo\": 42}";
                using (MemoryStream in1 = new MemoryStream(Encoding.UTF8.GetBytes(content)))
                {
                    Assert.ThrowsException<IOException>(() =>
                    {
                        _masterkeyFileAccess.Load(in1, "asd");
                    });
                }
            }

            [TestMethod]
            [DisplayName("Test Load Malformed Content")]
            public void TestLoadMalformed()
            {
                string content = "not even json";
                using (MemoryStream in1 = new MemoryStream(Encoding.UTF8.GetBytes(content)))
                {
                    Assert.ThrowsException<IOException>(() =>
                    {
                        _masterkeyFileAccess.Load(in1, "asd");
                    });
                }
            }
        }

        [TestClass]
        public class UnlockTests
        {
            private MasterkeyFile _keyFile;
            private MasterkeyFileAccess _masterkeyFileAccess;

            [TestInitialize]
            public void Setup()
            {
                _keyFile = new MasterkeyFile();
                _masterkeyFileAccess = new MasterkeyFileAccess(new byte[0], SecureRandomMock.NULL_RANDOM);

                _keyFile.Version = 3;
                _keyFile.ScryptSalt = new byte[8];
                _keyFile.ScryptCostParam = 2;
                _keyFile.ScryptBlockSize = 8;
                _keyFile.EncMasterKey = Convert.FromBase64String("mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==");
                _keyFile.MacMasterKey = Convert.FromBase64String("mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==");
                _keyFile.VersionMac = Convert.FromBase64String("iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=");
            }

            [TestMethod]
            [DisplayName("Test Unlock With Correct Password")]
            public void TestUnlockWithCorrectPassword()
            {
                var key = _masterkeyFileAccess.Unlock(_keyFile, "asd");
                Assert.IsNotNull(key);
            }

            [TestMethod]
            [DisplayName("Test Unlock With Incorrect Password")]
            public void TestUnlockWithIncorrectPassword()
            {
                Assert.ThrowsException<CryptomatorLib.Api.InvalidCredentialException>(() =>
                {
                    _masterkeyFileAccess.Unlock(_keyFile, "qwe");
                });
            }

            [TestMethod]
            [DisplayName("Test Unlock With Incorrect Pepper")]
            public void TestUnlockWithIncorrectPepper()
            {
                MasterkeyFileAccess masterkeyFileAccess = new MasterkeyFileAccess(new byte[1], SecureRandomMock.NULL_RANDOM);

                Assert.ThrowsException<CryptomatorLib.Api.InvalidCredentialException>(() =>
                {
                    masterkeyFileAccess.Unlock(_keyFile, "qwe");
                });
            }
        }

        [TestClass]
        public class LockTests
        {
            private PerpetualMasterkey _key;
            private MasterkeyFileAccess _masterkeyFileAccess;

            [TestInitialize]
            public void Setup()
            {
                _key = new PerpetualMasterkey(new byte[64]);
                _masterkeyFileAccess = new MasterkeyFileAccess(new byte[0], SecureRandomMock.NULL_RANDOM);
            }

            [TestMethod]
            [DisplayName("Test Lock Creates Expected Values")]
            public void TestLock()
            {
                MasterkeyFile keyFile = _masterkeyFileAccess.Lock(_key, "asd", 3, 2);

                Assert.AreEqual(3, keyFile.Version);
                CollectionAssert.AreEqual(new byte[8], keyFile.ScryptSalt);
                Assert.AreEqual(2, keyFile.ScryptCostParam);
                Assert.AreEqual(8, keyFile.ScryptBlockSize);
                CollectionAssert.AreEqual(Convert.FromBase64String("mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q=="), keyFile.EncMasterKey);
                CollectionAssert.AreEqual(Convert.FromBase64String("mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q=="), keyFile.MacMasterKey);
                CollectionAssert.AreEqual(Convert.FromBase64String("iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA="), keyFile.VersionMac);
            }

            [TestMethod]
            [DisplayName("Test Lock With Different Passwords")]
            public void TestLockWithDifferentPasswords()
            {
                MasterkeyFile keyFile1 = _masterkeyFileAccess.Lock(_key, "asd", 8, 2);
                MasterkeyFile keyFile2 = _masterkeyFileAccess.Lock(_key, "qwe", 8, 2);

                CollectionAssert.AreNotEqual(keyFile1.EncMasterKey, keyFile2.EncMasterKey);
            }

            [TestMethod]
            [DisplayName("Test Lock With Different Peppers")]
            public void TestLockWithDifferentPeppers()
            {
                byte[] pepper1 = new byte[] { 0x01 };
                byte[] pepper2 = new byte[] { 0x02 };
                MasterkeyFileAccess masterkeyFileAccess1 = new MasterkeyFileAccess(pepper1, SecureRandomMock.NULL_RANDOM);
                MasterkeyFileAccess masterkeyFileAccess2 = new MasterkeyFileAccess(pepper2, SecureRandomMock.NULL_RANDOM);

                MasterkeyFile keyFile1 = masterkeyFileAccess1.Lock(_key, "asd", 8, 2);
                MasterkeyFile keyFile2 = masterkeyFileAccess2.Lock(_key, "asd", 8, 2);

                CollectionAssert.AreNotEqual(keyFile1.EncMasterKey, keyFile2.EncMasterKey);
            }
        }

        [TestMethod]
        [DisplayName("Test Persist And Load")]
        public void TestPersistAndLoad()
        {
            // Create temporary file
            string tempFilePath = Path.GetTempFileName();
            try
            {
                // Persist the masterkey to a file
                _masterkeyFileAccess.Persist(_key, tempFilePath, "asd");

                // Load the masterkey from the file
                PerpetualMasterkey loaded = _masterkeyFileAccess.Load(tempFilePath, "asd");

                // Verify the loaded key matches the original
                CollectionAssert.AreEqual(_key.GetRaw(), loaded.GetRaw());
            }
            finally
            {
                // Clean up the temporary file
                if (File.Exists(tempFilePath))
                {
                    File.Delete(tempFilePath);
                }
            }
        }
    }
}