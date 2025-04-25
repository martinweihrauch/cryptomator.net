using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Common;
using System;
using System.Security.Cryptography;

namespace CryptomatorLib.Tests.Common
{
    [TestClass]
    public class MessageDigestSupplierTest
    {
        [TestMethod]
        [DisplayName("Test Constructor With Invalid Digest Algorithm")]
        public void TestConstructorWithInvalidDigest()
        {
            // Test creating a MessageDigestSupplier with an invalid algorithm name
            Assert.ThrowsException<ArgumentException>(() =>
                new MessageDigestSupplier("FOO3000"));
        }

        [TestMethod]
        [DisplayName("Test Get SHA256 Instance")]
        public void TestGetSha256()
        {
            // Get a MessageDigest from the supplier
            using (var lease1 = MessageDigestSupplier.SHA256.Instance())
            {
                Assert.IsNotNull(lease1);
                Assert.IsNotNull(lease1.Get());
            }

            // Get another MessageDigest from the supplier (should be pooled and reused)
            using (var lease2 = MessageDigestSupplier.SHA256.Instance())
            {
                Assert.IsNotNull(lease2);
                Assert.IsNotNull(lease2.Get());
            }
        }

        [TestMethod]
        [DisplayName("Test Direct Use Of MessageDigest")]
        public void TestDirectUseOfMessageDigest()
        {
            // Create test data
            byte[] data = new byte[] { 1, 2, 3, 4, 5 };

            // Use the message digest
            byte[] hash1;
            using (var lease = MessageDigestSupplier.SHA256.Instance())
            {
                var digest = lease.Get();
                digest.TransformFinalBlock(data, 0, data.Length);
                hash1 = digest.Hash;
            }

            // Use another message digest (should be reset and reused)
            byte[] hash2;
            using (var lease = MessageDigestSupplier.SHA256.Instance())
            {
                var digest = lease.Get();
                digest.TransformFinalBlock(data, 0, data.Length);
                hash2 = digest.Hash;
            }

            // Both digests should produce the same hash for the same data
            CollectionAssert.AreEqual(hash1, hash2);
        }
    }
}