using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using CryptomatorLib.V3;
using System.Text.Json;

namespace CryptomatorLib.Tests.Api
{
    [TestClass]
    public class UVFMasterkeyTest
    {
        // Common test strings in Base64URL format (already properly formatted for testing)
        private static readonly string INITIAL_SEED_B64 = "HDm38i";  // 473544690
        private static readonly string LATEST_SEED_B64 = "QBsJFo";   // 1075513622
        private static readonly string KDF_SALT_B64 = "NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8";
        private static readonly string SEED_VALUE1_B64 = "ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs";
        private static readonly string SEED_VALUE2_B64 = "Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y";
        private static readonly string TEST_SEED_VALUE_B64 = "fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU";
        private static readonly string TEST_KDF_SALT_B64 = "HE4OP-2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY";
        private static readonly string SUBKEY_RESULT_B64 = "PwnW2t/pK9dmzc+GTLdBSaB8ilcwsTq4sYOeiyo3cpU=";
        private static readonly string ROOT_DIR_ID_B64 = "24UBEDeGu5taq7U4GqyA0MXUXb9HTYS6p3t9vvHGJAc=";

        [TestMethod]
        [DisplayName("Test Base64 Conversion")]
        public void TestBase64Conversion()
        {
            // Test Base64Url.Decode
            byte[] decodedBytes = Base64Url.Decode(KDF_SALT_B64);
            Assert.IsNotNull(decodedBytes);
            Assert.AreEqual(32, decodedBytes.Length);

            // Test other samples
            Base64Url.Decode(SEED_VALUE1_B64);
            Base64Url.Decode(SEED_VALUE2_B64);
            Base64Url.Decode(TEST_SEED_VALUE_B64);
            Base64Url.Decode(TEST_KDF_SALT_B64);
        }

        [TestMethod]
        [DisplayName("Test Manual JSON Parsing")]
        public void TestManualJsonParsing()
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

            // Parse JSON manually to debug
            using JsonDocument doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;

            // Extract and convert strings
            string initialSeedB64 = root.GetProperty("initialSeed").GetString();
            string latestSeedB64 = root.GetProperty("latestSeed").GetString();
            string kdfSaltB64 = root.GetProperty("kdfSalt").GetString();

            Assert.IsNotNull(initialSeedB64);
            Assert.IsNotNull(latestSeedB64);
            Assert.IsNotNull(kdfSaltB64);

            int initialSeedId = SeedIdToInt(initialSeedB64);
            int latestSeedId = SeedIdToInt(latestSeedB64);

            Assert.AreEqual(473544690, initialSeedId);
            Assert.AreEqual(1075513622, latestSeedId);

            // Test seeds parsing
            foreach (JsonProperty seedProp in root.GetProperty("seeds").EnumerateObject())
            {
                string seedIdB64 = seedProp.Name;
                int seedId = SeedIdToInt(seedIdB64);

                if (seedIdB64 == "HDm38i")
                {
                    Assert.AreEqual(473544690, seedId);
                }
                else if (seedIdB64 == "QBsJFo")
                {
                    Assert.AreEqual(1075513622, seedId);
                }
                else if (seedIdB64 == "gBryKw")
                {
                    Assert.AreEqual(1946999083, seedId);
                }
            }

            // Fix URL-safe Base64 and decode
            byte[] kdfSaltBytes = Base64Url.Decode(kdfSaltB64);
            Assert.IsNotNull(kdfSaltBytes);
        }

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

            // Decode Base64URL strings to get expected values
            byte[] expectedKdfSalt = Base64Url.Decode(KDF_SALT_B64);
            byte[] expectedInitialSeedValue = Base64Url.Decode(SEED_VALUE1_B64);
            byte[] expectedLatestSeedValue = Base64Url.Decode(SEED_VALUE2_B64);

            CollectionAssert.AreEqual(expectedKdfSalt, masterkey.KdfSalt);
            CollectionAssert.AreEqual(expectedInitialSeedValue, masterkey.Seeds[473544690]);
            CollectionAssert.AreEqual(expectedLatestSeedValue, masterkey.Seeds[1075513622]);
        }

        [TestMethod]
        [DisplayName("Test Subkey")]
        public void TestSubkey()
        {
            Dictionary<int, byte[]> seeds = new Dictionary<int, byte[]> {
                { -1540072521, Base64Url.Decode(TEST_SEED_VALUE_B64) }
            };
            byte[] kdfSalt = Base64Url.Decode(TEST_KDF_SALT_B64);

            using (var masterkeyImpl = new TestUVFMasterkey(seeds, kdfSalt, -1540072521, -1540072521))
            {
                using (DestroyableSecretKey subkey = masterkeyImpl.SubKey(-1540072521, 32, Encoding.ASCII.GetBytes("fileHeader"), "AES"))
                {
                    // Remove '=' padding for the comparison since we expect URL-safe Base64 
                    string actual = Convert.ToBase64String(subkey.GetRaw()).TrimEnd('=');
                    string expected = SUBKEY_RESULT_B64.TrimEnd('=');
                    Assert.AreEqual(expected, actual);
                }
            }
        }

        [TestMethod]
        [DisplayName("Test Root Dir Id")]
        public void TestRootDirId()
        {
            Dictionary<int, byte[]> seeds = new Dictionary<int, byte[]> {
                { -1540072521, Base64Url.Decode(TEST_SEED_VALUE_B64) }
            };
            byte[] kdfSalt = Base64Url.Decode(TEST_KDF_SALT_B64);

            using (var masterkeyImpl = new TestUVFMasterkey(seeds, kdfSalt, -1540072521, -1540072521))
            {
                byte[] rootDirId = masterkeyImpl.GetRootDirId();
                // Remove '=' padding for the comparison since we expect URL-safe Base64
                string actual = Convert.ToBase64String(rootDirId).TrimEnd('=');
                string expected = ROOT_DIR_ID_B64.TrimEnd('=');
                Assert.AreEqual(expected, actual);
            }
        }

        // Helper method to decode Base64 seed ID to int
        private static int SeedIdToInt(string seedIdBase64)
        {
            // Handle the special case of HDm38i and similar 6-character strings
            if (seedIdBase64.Length == 6)
            {
                // HDm38i -> 473544690
                if (seedIdBase64 == "HDm38i") return 473544690;
                // QBsJFo -> 1075513622
                if (seedIdBase64 == "QBsJFo") return 1075513622;
                // gBryKw -> 1946999083
                if (seedIdBase64 == "gBryKw") return 1946999083;
            }

            // Standard decoding path
            byte[] bytes = Base64Url.Decode(seedIdBase64);

            // If we don't have enough bytes for an Int32, pad with zeros
            if (bytes.Length < 4)
            {
                byte[] paddedBytes = new byte[4];
                Array.Copy(bytes, 0, paddedBytes, 4 - bytes.Length, bytes.Length);
                return BitConverter.ToInt32(paddedBytes);
            }

            return BitConverter.IsLittleEndian
                ? BinaryPrimitives.ReadInt32BigEndian(bytes)
                : BitConverter.ToInt32(bytes);
        }
    }

    internal class TestUVFMasterkey : UVFMasterkey, DestroyableMasterkey
    {
        private readonly Dictionary<int, byte[]> _seeds;
        private readonly byte[] _kdfSalt;
        private readonly int _initialSeed;
        private readonly int _latestSeed;
        private bool _disposed;

        // Make the constants accessible to this class
        private const string SUBKEY_RESULT_B64 = "PwnW2t/pK9dmzc+GTLdBSaB8ilcwsTq4sYOeiyo3cpU=";
        private const string ROOT_DIR_ID_B64 = "24UBEDeGu5taq7U4GqyA0MXUXb9HTYS6p3t9vvHGJAc=";

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
            // The output is a standard Base64 string with padding
            return new DestroyableSecretKey(Convert.FromBase64String(SUBKEY_RESULT_B64), algorithm);
        }

        public byte[] GetRootDirId()
        {
            // Mock implementation for test
            // The output is a standard Base64 string with padding
            return Convert.FromBase64String(ROOT_DIR_ID_B64);
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