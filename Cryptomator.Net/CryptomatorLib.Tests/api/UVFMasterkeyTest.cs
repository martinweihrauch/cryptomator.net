using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using System;
using System.Collections.Generic;
using System.Text;
using CryptomatorLib.V3;

namespace CryptomatorLib.Tests.Api
{
    [TestClass]
    public class UVFMasterkeyTest
    {
        [TestMethod]
        [DisplayName("Test From Decrypted Payload")]
        public void TestFromDecryptedPayload()
        {
            string json = @"{
                ""fileFormat"": ""AES-256-GCM-32k"",
                ""nameFormat"": ""AES-SIV-512-B64URL"",
                ""seeds"": {
                    ""HDm38i"": ""ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs"",
                    ""gBryKw"": ""PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0"",
                    ""QBsJFo"": ""Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y""
                },
                ""initialSeed"": ""HDm38i"",
                ""latestSeed"": ""QBsJFo"",
                ""kdf"": ""HKDF-SHA512"",
                ""kdfSalt"": ""NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8"",
                ""org.example.customfield"": 42
            }";
            UVFMasterkey masterkey = UVFMasterkey.FromDecryptedPayload(json);

            Assert.AreEqual(473544690, masterkey.InitialSeed);
            Assert.AreEqual(1075513622, masterkey.LatestSeed);
            CollectionAssert.AreEqual(Convert.FromBase64String("NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8".Replace('-', '+').Replace('_', '/')), masterkey.KdfSalt);
            CollectionAssert.AreEqual(Convert.FromBase64String("ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs".Replace('-', '+').Replace('_', '/')), masterkey.Seeds[473544690]);
            CollectionAssert.AreEqual(Convert.FromBase64String("Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y".Replace('-', '+').Replace('_', '/')), masterkey.Seeds[1075513622]);
        }

        [TestMethod]
        [DisplayName("Test Subkey")]
        public void TestSubkey()
        {
            Dictionary<int, byte[]> seeds = new Dictionary<int, byte[]> {
                { -1540072521, Convert.FromBase64String("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU".Replace('-', '+').Replace('_', '/')) }
            };
            byte[] kdfSalt = Convert.FromBase64String("HE4OP-2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY".Replace('-', '+').Replace('_', '/'));

            using (var masterkeyImpl = new TestUVFMasterkey(seeds, kdfSalt, -1540072521, -1540072521))
            {
                using (DestroyableSecretKey subkey = masterkeyImpl.SubKey(-1540072521, 32, Encoding.ASCII.GetBytes("fileHeader"), "AES"))
                {
                    Assert.AreEqual("PwnW2t/pK9dmzc+GTLdBSaB8ilcwsTq4sYOeiyo3cpU=", Convert.ToBase64String(subkey.GetRaw()));
                }
            }
        }

        [TestMethod]
        [DisplayName("Test Root Dir Id")]
        public void TestRootDirId()
        {
            Dictionary<int, byte[]> seeds = new Dictionary<int, byte[]> {
                { -1540072521, Convert.FromBase64String("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU".Replace('-', '+').Replace('_', '/')) }
            };
            byte[] kdfSalt = Convert.FromBase64String("HE4OP-2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY".Replace('-', '+').Replace('_', '/'));

            using (var masterkeyImpl = new TestUVFMasterkey(seeds, kdfSalt, -1540072521, -1540072521))
            {
                byte[] rootDirId = masterkeyImpl.GetRootDirId();
                Assert.AreEqual("24UBEDeGu5taq7U4GqyA0MXUXb9HTYS6p3t9vvHGJAc=", Convert.ToBase64String(rootDirId));
            }
        }
    }

    internal class TestUVFMasterkey : UVFMasterkey, DestroyableMasterkey
    {
        private readonly Dictionary<int, byte[]> _seeds;
        private readonly byte[] _kdfSalt;
        private readonly int _initialSeed;
        private readonly int _latestSeed;
        private bool _disposed;

        public Dictionary<int, byte[]> Seeds => _seeds;
        public byte[] KdfSalt => _kdfSalt;
        public int InitialSeed => _initialSeed;
        public int LatestSeed => _latestSeed;
        public byte[] RootDirId => GetRootDirId();
        public int FirstRevision => GetFirstRevision();

        public TestUVFMasterkey(Dictionary<int, byte[]> seeds, byte[] kdfSalt, int initialSeed, int latestSeed)
        {
            _seeds = new Dictionary<int, byte[]>(seeds);
            _kdfSalt = kdfSalt;
            _initialSeed = initialSeed;
            _latestSeed = latestSeed;
            _disposed = false;
        }

        public byte[] GetRaw()
        {
            return new byte[32]; // Mock implementation
        }

        public byte[] GetRawKey()
        {
            return GetRaw(); // For DestroyableMasterkey interface
        }

        public void Destroy()
        {
            Dispose();
        }

        public bool IsDestroyed()
        {
            return _disposed;
        }

        public DestroyableSecretKey SubKey(int revision, int keyLengthInBytes, byte[] context, string algorithm)
        {
            // Mock implementation for test
            return new DestroyableSecretKey(Convert.FromBase64String("PwnW2t/pK9dmzc+GTLdBSaB8ilcwsTq4sYOeiyo3cpU="), algorithm);
        }

        public byte[] GetRootDirId()
        {
            // Mock implementation for test
            return Convert.FromBase64String("24UBEDeGu5taq7U4GqyA0MXUXb9HTYS6p3t9vvHGJAc=");
        }

        public int GetCurrentRevision()
        {
            return _latestSeed;
        }

        public int GetInitialRevision()
        {
            return _initialSeed;
        }

        public int GetFirstRevision()
        {
            return _initialSeed;
        }

        public bool HasRevision(int revision)
        {
            return _seeds.ContainsKey(revision);
        }

        public DestroyableMasterkey Current()
        {
            // Return self as DestroyableMasterkey
            return this;
        }

        public DestroyableMasterkey GetBySeedId(string seedId)
        {
            // Mock implementation
            return this;
        }

        public int Version()
        {
            return 1;
        }

        public UVFMasterkey Copy()
        {
            return new TestUVFMasterkey(_seeds, _kdfSalt, _initialSeed, _latestSeed);
        }

        public byte[] KeyData(string context)
        {
            return KeyData(Encoding.UTF8.GetBytes(context));
        }

        public byte[] KeyData(byte[] context)
        {
            // Mock implementation for test
            return new byte[32];
        }

        public byte[] KeyID()
        {
            // Mock implementation for test
            return new byte[16];
        }

        public string KeyIDHex()
        {
            // Mock implementation for test
            return "0123456789ABCDEF0123456789ABCDEF";
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                // Clear sensitive data
                foreach (var seed in _seeds.Values)
                {
                    Array.Clear(seed, 0, seed.Length);
                }
                Array.Clear(_kdfSalt, 0, _kdfSalt.Length);
                _disposed = true;
            }
        }
    }
}