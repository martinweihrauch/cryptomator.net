using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using System;
using System.Collections.Generic;
using System.Text;

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

            using (UVFMasterkey masterkey = new UVFMasterkey(seeds, kdfSalt, -1540072521, -1540072521))
            {
                using (DestroyableSecretKey subkey = masterkey.SubKey(-1540072521, 32, Encoding.ASCII.GetBytes("fileHeader"), "AES"))
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

            using (UVFMasterkey masterkey = new UVFMasterkey(seeds, kdfSalt, -1540072521, -1540072521))
            {
                Assert.AreEqual("24UBEDeGu5taq7U4GqyA0MXUXb9HTYS6p3t9vvHGJAc=", Convert.ToBase64String(masterkey.RootDirId()));
            }
        }
    }
}