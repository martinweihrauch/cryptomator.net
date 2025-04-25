using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Common;
using System;
using System.Text;
using System.Security.Cryptography;

namespace CryptomatorLib.Tests.Common
{
    [TestClass]
    public class MasterkeyTest
    {
        [TestMethod]
        [DisplayName("Test Create Masterkey")]
        public void TestCreateMasterkey()
        {
            // Create a new masterkey
            using (var masterkey = Masterkey.CreateNew())
            {
                // Verify the masterkey has a valid raw key
                Assert.IsNotNull(masterkey.RawKey);
                Assert.AreEqual(Masterkey.KeyLength, masterkey.RawKey.Length);
            }
        }

        [TestMethod]
        [DisplayName("Test Create From Raw Key")]
        public void TestCreateFromRawKey()
        {
            // Create a random key
            byte[] keyBytes = new byte[Masterkey.KeyLength];
            new SecureRandom().NextBytes(keyBytes);

            // Create a masterkey from the raw key
            using (var masterkey = Masterkey.CreateFromRaw(keyBytes))
            {
                // Verify the raw key was set correctly
                CollectionAssert.AreEqual(keyBytes, masterkey.RawKey);
            }
        }

        [TestMethod]
        [DisplayName("Test Create From Raw Key With Invalid Length")]
        public void TestCreateFromRawKeyWithInvalidLength()
        {
            // Create a key with invalid length
            byte[] keyBytes = new byte[Masterkey.KeyLength - 1]; // Too short

            // Attempt to create a masterkey with the invalid key
            Assert.ThrowsException<ArgumentException>(() =>
                Masterkey.CreateFromRaw(keyBytes));
        }

        [TestMethod]
        [DisplayName("Test Encrypt And Decrypt Masterkey")]
        public void TestEncryptAndDecryptMasterkey()
        {
            // Create a passphrase for encryption
            string passphrase = "test-passphrase";

            // Create a masterkey
            using (var originalMasterkey = Masterkey.CreateNew())
            {
                // Encrypt the masterkey to create a masterkey file
                MasterkeyFile masterkeyFile = originalMasterkey.CreateMasterkeyFile(passphrase);

                // Verify the masterkey file contains the expected encrypted data
                Assert.IsNotNull(masterkeyFile.ScryptSalt);
                Assert.IsNotNull(masterkeyFile.PrimaryMasterkey);
                Assert.IsNotNull(masterkeyFile.PrimaryMasterkeyNonce);

                // Decrypt the masterkey from the file
                using (var decryptedMasterkey = Masterkey.DecryptMasterkey(masterkeyFile, passphrase))
                {
                    // Verify the decrypted masterkey matches the original
                    CollectionAssert.AreEqual(originalMasterkey.RawKey, decryptedMasterkey.RawKey);
                }
            }
        }

        [TestMethod]
        [DisplayName("Test Decrypt With Wrong Passphrase")]
        public void TestDecryptWithWrongPassphrase()
        {
            // Create a masterkey and encrypt it
            using (var originalMasterkey = Masterkey.CreateNew())
            {
                MasterkeyFile masterkeyFile = originalMasterkey.CreateMasterkeyFile("correct-passphrase");

                // Attempt to decrypt with wrong passphrase
                Assert.ThrowsException<InvalidCredentialException>(() =>
                    Masterkey.DecryptMasterkey(masterkeyFile, "wrong-passphrase"));
            }
        }

        [TestMethod]
        [DisplayName("Test Destroy Masterkey")]
        public void TestDestroyMasterkey()
        {
            // Create a masterkey
            var masterkey = Masterkey.CreateNew();

            // Get a copy of the raw key for verification
            byte[] rawKeyCopy = new byte[masterkey.RawKey.Length];
            Array.Copy(masterkey.RawKey, rawKeyCopy, rawKeyCopy.Length);

            // Destroy the masterkey
            masterkey.Destroy();

            // Verify the raw key has been zeroed out
            for (int i = 0; i < masterkey.RawKey.Length; i++)
            {
                Assert.AreEqual(0, masterkey.RawKey[i]);
            }

            // Verify our copy still has non-zero values (sanity check)
            bool allZeroes = true;
            for (int i = 0; i < rawKeyCopy.Length; i++)
            {
                if (rawKeyCopy[i] != 0)
                {
                    allZeroes = false;
                    break;
                }
            }
            Assert.IsFalse(allZeroes, "Original key data should not be all zeroes");
        }
    }
}