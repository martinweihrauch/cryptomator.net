using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Common;
using System;
using System.Security.Cryptography;
using Moq;

namespace CryptomatorLib.Tests.Common
{
    [TestClass]
    public class DestroyableSecretKeyTest
    {
        [TestMethod]
        [DisplayName("Test Create Secret Key")]
        public void TestCreateSecretKey()
        {
            // Create a key
            byte[] keyBytes = new byte[] { 1, 2, 3, 4, 5 };
            string algorithm = "TEST";

            // Create a DestroyableSecretKey
            var key = new DestroyableSecretKey(keyBytes, algorithm);

            // Verify properties
            Assert.AreEqual(algorithm, key.Algorithm);
            CollectionAssert.AreEqual(keyBytes, key.GetKeyBytes());
        }

        [TestMethod]
        [DisplayName("Test Equals And HashCode")]
        public void TestEqualsAndHashCode()
        {
            // Create two identical keys
            byte[] keyBytes1 = new byte[] { 1, 2, 3, 4, 5 };
            byte[] keyBytes2 = new byte[] { 1, 2, 3, 4, 5 };
            var key1 = new DestroyableSecretKey(keyBytes1, "TEST");
            var key2 = new DestroyableSecretKey(keyBytes2, "TEST");

            // Create a different key
            byte[] keyBytes3 = new byte[] { 5, 4, 3, 2, 1 };
            var key3 = new DestroyableSecretKey(keyBytes3, "TEST");

            // Create a key with different algorithm
            var key4 = new DestroyableSecretKey(keyBytes1, "DIFFERENT");

            // Test equals
            Assert.AreEqual(key1, key2);
            Assert.AreNotEqual<object>(key1, key3);
            Assert.AreNotEqual<object>(key1, key4);
            Assert.AreNotEqual<object>(key1, null);
            Assert.AreNotEqual<object>(key1, "not a key");

            // Test hashCode
            Assert.AreEqual(key1.GetHashCode(), key2.GetHashCode());
            Assert.AreNotEqual(key1.GetHashCode(), key3.GetHashCode());
            Assert.AreNotEqual(key1.GetHashCode(), key4.GetHashCode());
        }

        [TestMethod]
        [DisplayName("Test Destroy")]
        public void TestDestroy()
        {
            // Create a key
            byte[] keyBytes = new byte[] { 1, 2, 3, 4, 5 };
            var key = new DestroyableSecretKey(keyBytes, "TEST");

            // Make a copy for verification
            byte[] keyBytesCopy = new byte[keyBytes.Length];
            Array.Copy(keyBytes, keyBytesCopy, keyBytes.Length);

            // Destroy the key
            key.Destroy();

            // Verify the key has been zeroed out
            byte[] destroyedKeyBytes = key.GetKeyBytes();
            for (int i = 0; i < destroyedKeyBytes.Length; i++)
            {
                Assert.AreEqual(0, destroyedKeyBytes[i]);
            }

            // Verify our copy is still intact (sanity check)
            CollectionAssert.AreEqual(keyBytesCopy, keyBytes);
        }

        [TestMethod]
        [DisplayName("Test IsDestroyed")]
        public void TestIsDestroyed()
        {
            // Create a key
            byte[] keyBytes = new byte[] { 1, 2, 3, 4, 5 };
            var key = new DestroyableSecretKey(keyBytes, "TEST");

            // Check initial state
            Assert.IsFalse(key.IsDestroyed());

            // Destroy the key
            key.Destroy();

            // Verify the key is marked as destroyed
            Assert.IsTrue(key.IsDestroyed());
        }

        [TestMethod]
        [DisplayName("Test Dispose")]
        public void TestDispose()
        {
            // Create a key
            byte[] keyBytes = new byte[] { 1, 2, 3, 4, 5 };
            var key = new DestroyableSecretKey(keyBytes, "TEST");

            // Dispose the key
            key.Dispose();

            // Verify the key is destroyed
            Assert.IsTrue(key.IsDestroyed());
            byte[] destroyedKeyBytes = key.GetKeyBytes();
            for (int i = 0; i < destroyedKeyBytes.Length; i++)
            {
                Assert.AreEqual(0, destroyedKeyBytes[i]);
            }
        }

        [TestMethod]
        [DisplayName("Test Generate Method Creates Valid Keys")]
        public void TestGenerateMethod()
        {
            // Arrange
            byte[] expectedKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            int keyLength = expectedKey.Length;
            string algorithm = "TEST";

            var mockRng = new Mock<RandomNumberGenerator>();
            mockRng.Setup(rng => rng.GetBytes(It.IsAny<byte[]>()))
                   .Callback<byte[]>(buffer => Buffer.BlockCopy(expectedKey, 0, buffer, 0, Math.Min(buffer.Length, expectedKey.Length)));

            // Act
            DestroyableSecretKey key = DestroyableSecretKey.Generate(mockRng.Object, algorithm, keyLength);

            // Assert
            Assert.IsNotNull(key);
            CollectionAssert.AreEqual(expectedKey, key.GetRaw());
            mockRng.Verify(rng => rng.GetBytes(It.IsAny<byte[]>()), Times.Once);
        }

        [TestMethod]
        [DisplayName("Constructor Fails For Null Algorithm")]
        public void TestConstructorFailsForNullAlgorithm()
        {
            Assert.ThrowsException<ArgumentNullException>(() =>
                new DestroyableSecretKey(new byte[16], null));
        }

        [TestMethod]
        [DisplayName("Constructor Fails For Invalid Length")]
        public void TestConstructorFailsForInvalidLength()
        {
            Assert.ThrowsException<ArgumentException>(() =>
                new DestroyableSecretKey(new byte[16], 0, -1, "TEST"));
        }

        [TestMethod]
        [DisplayName("Constructor Fails For Invalid Offset")]
        public void TestConstructorFailsForInvalidOffset()
        {
            Assert.ThrowsException<ArgumentException>(() =>
                new DestroyableSecretKey(new byte[16], -1, 16, "TEST"));
        }

        [TestMethod]
        [DisplayName("Constructor Fails For Invalid Length And Offset")]
        public void TestConstructorFailsForInvalidLengthAndOffset()
        {
            Assert.ThrowsException<ArgumentException>(() =>
                new DestroyableSecretKey(new byte[16], 8, 16, "TEST"));
        }

        [TestMethod]
        [DisplayName("Constructor Creates Local Copy")]
        public void TestConstructorCreatesLocalCopy()
        {
            // Arrange
            byte[] orig = new byte[] { 1, 2, 3, 4, 5 };

            // Act
            DestroyableSecretKey key = new DestroyableSecretKey(orig, "TEST");

            // Modify original array
            Array.Clear(orig, 0, orig.Length);

            // Assert
            CollectionAssert.AreNotEqual(orig, key.GetRaw());
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4, 5 }, key.GetRaw());
        }

        [TestClass]
        public class UndestroyedKeyTests
        {
            private byte[] _rawKey;
            private DestroyableSecretKey _key;

            [TestInitialize]
            public void Setup()
            {
                _rawKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
                _key = new DestroyableSecretKey(_rawKey, "EXAMPLE");
            }

            [TestMethod]
            [DisplayName("IsDestroyed Returns False For Undestroyed Key")]
            public void TestIsDestroyed()
            {
                Assert.IsFalse(_key.IsDestroyed());
            }

            [TestMethod]
            [DisplayName("Algorithm Property Returns Algorithm Name")]
            public void TestAlgorithm()
            {
                Assert.AreEqual("EXAMPLE", _key.Algorithm);
            }

            [TestMethod]
            [DisplayName("Format Property Returns RAW")]
            public void TestFormat()
            {
                Assert.AreEqual("RAW", _key.Format);
            }

            [TestMethod]
            [DisplayName("GetRaw Returns Raw Key")]
            public void TestGetRaw()
            {
                CollectionAssert.AreEqual(_rawKey, _key.GetRaw());
            }

            [TestMethod]
            [DisplayName("Copy Returns Equal Copy")]
            public void TestCopy()
            {
                // Act
                DestroyableSecretKey copy = _key.Copy();

                // Assert
                Assert.AreNotSame(_key, copy);
                CollectionAssert.AreEqual(_key.GetRaw(), copy.GetRaw());
                Assert.AreEqual(_key.Algorithm, copy.Algorithm);
            }

            [TestMethod]
            [DisplayName("Dispose Destroys Key")]
            public void TestDispose()
            {
                // Act
                _key.Dispose();

                // Assert
                Assert.IsTrue(_key.IsDestroyed());
            }
        }

        [TestClass]
        public class DestroyedKeyTests
        {
            private DestroyableSecretKey _key;

            [TestInitialize]
            public void Setup()
            {
                byte[] keyBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
                _key = new DestroyableSecretKey(keyBytes, "EXAMPLE");
                _key.Destroy();
            }

            [TestMethod]
            [DisplayName("IsDestroyed Returns True For Destroyed Key")]
            public void TestIsDestroyed()
            {
                Assert.IsTrue(_key.IsDestroyed());
            }

            [TestMethod]
            [DisplayName("Algorithm Property Throws For Destroyed Key")]
            public void TestAlgorithm()
            {
                Assert.ThrowsException<InvalidOperationException>(() => _ = _key.Algorithm);
            }

            [TestMethod]
            [DisplayName("Format Property Throws For Destroyed Key")]
            public void TestFormat()
            {
                Assert.ThrowsException<InvalidOperationException>(() => _ = _key.Format);
            }

            [TestMethod]
            [DisplayName("GetRaw Throws For Destroyed Key")]
            public void TestGetRaw()
            {
                Assert.ThrowsException<InvalidOperationException>(() => _key.GetRaw());
            }

            [TestMethod]
            [DisplayName("Copy Throws For Destroyed Key")]
            public void TestCopy()
            {
                Assert.ThrowsException<InvalidOperationException>(() => _key.Copy());
            }
        }
    }
}