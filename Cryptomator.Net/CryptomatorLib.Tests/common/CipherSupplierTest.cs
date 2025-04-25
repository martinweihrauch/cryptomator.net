using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Common;
using System;
using System.Security.Cryptography;

namespace CryptomatorLib.Tests.Common
{
    [TestClass]
    public class CipherSupplierTest
    {
        [TestMethod]
        [DisplayName("Test Get Unknown Cipher")]
        public void TestGetUnknownCipher()
        {
            // Test creating a CipherSupplier with an invalid algorithm name
            Assert.ThrowsException<ArgumentException>(() =>
                new CipherSupplier("doesNotExist"));
        }

        [TestMethod]
        [DisplayName("Test Get Cipher With Invalid Key")]
        public void TestGetCipherWithInvalidKey()
        {
            // Create a CipherSupplier
            CipherSupplier supplier = new CipherSupplier("AES-CBC");

            // Create an invalid key (wrong size for AES)
            byte[] keyData = new byte[13]; // AES keys should be 16, 24, or 32 bytes
            var key = new DestroyableSecretKey(keyData, "AES");

            // Create valid IV
            byte[] iv = new byte[16];

            // Attempt to get a cipher with the invalid key
            var exception = Assert.ThrowsException<ArgumentException>(() =>
                supplier.EncryptionCipher(key, iv));

            // Verify the exception message contains expected text
            StringAssert.Contains(exception.Message, "Invalid key");
        }

        [TestMethod]
        [DisplayName("Test Get Cipher With Invalid Parameters")]
        public void TestGetCipherWithInvalidParameters()
        {
            // Create a CipherSupplier for AES-CBC
            CipherSupplier supplier = new CipherSupplier("AES-CBC");

            // Create a valid key
            byte[] keyData = new byte[16]; // Valid 128-bit AES key
            var key = new DestroyableSecretKey(keyData, "AES");

            // Create invalid IV (wrong size for AES-CBC)
            byte[] invalidIv = new byte[8]; // AES-CBC requires 16-byte IV

            // Attempt to get a cipher with the invalid IV
            var exception = Assert.ThrowsException<ArgumentException>(() =>
                supplier.EncryptionCipher(key, invalidIv));

            // Verify the exception message contains expected text
            StringAssert.Contains(exception.Message, "Invalid parameter");
        }

        [TestMethod]
        [DisplayName("Test Get Valid Cipher")]
        public void TestGetValidCipher()
        {
            // Create a CipherSupplier for AES-GCM
            CipherSupplier supplier = CipherSupplier.AES_GCM;

            // Create a valid key
            byte[] keyData = new byte[32]; // 256-bit AES key
            var key = new DestroyableSecretKey(keyData, "AES");

            // Create valid nonce for GCM
            byte[] nonce = new byte[12]; // GCM typically uses 12-byte nonce

            // Get encryption cipher
            using (var lease = supplier.EncryptionCipher(key, nonce))
            {
                Assert.IsNotNull(lease);
                Assert.IsNotNull(lease.Get());
            }

            // Get decryption cipher
            using (var lease = supplier.DecryptionCipher(key, nonce))
            {
                Assert.IsNotNull(lease);
                Assert.IsNotNull(lease.Get());
            }
        }
    }
}