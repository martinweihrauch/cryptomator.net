using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using CryptomatorLib.Tests.Common;
using CryptomatorLib.Tests.Streams;
using CryptomatorLib.V3;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptomatorLib.Tests.Api
{
    [TestClass]
    public class CryptoLibIntegrationTest
    {
        private static readonly RandomNumberGenerator RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
        private static readonly string UVF_PAYLOAD = @"{
    ""fileFormat"": ""AES-256-GCM-32k"",
    ""nameFormat"": ""AES-SIV-512-B64URL"",
    ""seeds"": {
        ""HDm38g"": ""ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs"",
        ""gBryKw"": ""PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0"",
        ""QBsJFg"": ""Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y""
    },
    ""initialSeed"": ""HDm38i"",
    ""latestSeed"": ""QBsJFo"",
    ""kdf"": ""HKDF-SHA512"",
    ""kdfSalt"": ""NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8"",
    ""org.example.customfield"": 42
}";

        // The Java test uses parameterized tests with a method source to provide different cryptors
        // In C#, we can't do this exactly the same way, so we'll create separate test methods

        private List<Cryptor> GetCryptors()
        {
            var cryptors = new List<Cryptor>();

            // Create a masterkey
            Dictionary<int, byte[]> seeds = new Dictionary<int, byte[]>
            {
                { -1540072521, Convert.FromBase64String("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU=".Replace('-', '+').Replace('_', '/')) }
            };
            byte[] kdfSalt = Convert.FromBase64String("HE4OP-2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY=".Replace('-', '+').Replace('_', '/'));
            UVFMasterkey masterkey = new UVFMasterkeyImpl(seeds, kdfSalt, -1540072521, -1540072521);

            // Create a CryptoFactory
            var factory = new CryptoFactoryImpl(masterkey);

            // Create a Cryptor
            cryptors.Add(factory.Create());

            return cryptors;
        }

        [TestMethod]
        [DisplayName("Test Decrypt Encrypted")]
        public void TestDecryptEncrypted()
        {
            // Get cryptors to test
            var cryptors = GetCryptors();

            foreach (var cryptor in cryptors)
            {
                using (cryptor)
                {
                    // Setup test data
                    int size = 1 * 1024 * 1024; // 1MB
                    var cleartextBuffer = new byte[size];
                    var ciphertextBuffer = new byte[2 * size]; // Ciphertext is larger due to headers and authentication data
                    var resultBuffer = new byte[size + 1];

                    // Create streams for encryption/decryption
                    using (var cleartextStream = new MemoryStream(cleartextBuffer))
                    using (var ciphertextStream = new MemoryStream(ciphertextBuffer))
                    using (var resultStream = new MemoryStream(resultBuffer))
                    {
                        // Create encrypting stream wrapper
                        using (var encryptingStream = new EncryptingStream(ciphertextStream, cryptor))
                        {
                            // Encrypt data
                            cleartextStream.CopyTo(encryptingStream);
                            encryptingStream.Flush();
                        }

                        // Reset ciphertext stream for reading
                        ciphertextStream.Position = 0;

                        // Create decrypting stream wrapper
                        using (var decryptingStream = new DecryptingStream(ciphertextStream, cryptor, true))
                        {
                            // Decrypt data
                            decryptingStream.CopyTo(resultStream);
                        }

                        // Verify the decrypted data matches the original
                        for (int i = 0; i < size; i++)
                        {
                            Assert.AreEqual(cleartextBuffer[i], resultBuffer[i], $"Mismatch at position {i}");
                        }
                    }
                }
            }
        }

        [TestMethod]
        [DisplayName("Test Decrypt Manipulated Encrypted")]
        public void TestDecryptManipulatedEncrypted()
        {
            // Get cryptors to test
            var cryptors = GetCryptors();

            foreach (var cryptor in cryptors)
            {
                using (cryptor)
                {
                    // Setup test data
                    int size = 1 * 1024 * 1024; // 1MB
                    var cleartextBuffer = new byte[size];
                    var ciphertextBuffer = new byte[2 * size]; // Ciphertext is larger due to headers and authentication data
                    var resultBuffer = new byte[size + 1];

                    // Create streams for encryption/decryption
                    using (var cleartextStream = new MemoryStream(cleartextBuffer))
                    using (var ciphertextStream = new MemoryStream(ciphertextBuffer))
                    {
                        // Create encrypting stream wrapper
                        using (var encryptingStream = new EncryptingStream(ciphertextStream, cryptor))
                        {
                            // Encrypt data
                            cleartextStream.CopyTo(encryptingStream);
                            encryptingStream.Flush();
                        }

                        // Manipulate the ciphertext
                        int firstByteOfFirstChunk = cryptor.FileHeaderCryptor().HeaderSize() + 1; // Not inside chunk MAC
                        ciphertextBuffer[firstByteOfFirstChunk] = (byte)~ciphertextBuffer[firstByteOfFirstChunk];

                        // Reset ciphertext stream for reading
                        ciphertextStream.Position = 0;

                        // Attempt to decrypt manipulated data - should throw AuthenticationFailedException
                        using (var decryptingStream = new DecryptingStream(ciphertextStream, cryptor, true))
                        using (var resultStream = new MemoryStream(resultBuffer))
                        {
                            // Should throw
                            Assert.ThrowsException<IOException>(() =>
                            {
                                try
                                {
                                    decryptingStream.CopyTo(resultStream);
                                }
                                catch (IOException ex) when (ex.InnerException is AuthenticationFailedException)
                                {
                                    throw; // Re-throw to be caught by the Assert.ThrowsException
                                }
                            });
                        }
                    }
                }
            }
        }

        [TestMethod]
        [DisplayName("Test Decrypt Manipulated Encrypted Skip Auth")]
        public void TestDecryptManipulatedEncryptedSkipAuth()
        {
            // Get cryptors to test
            var cryptors = GetCryptors();

            foreach (var cryptor in cryptors)
            {
                using (cryptor)
                {
                    // Skip test if cryptor doesn't support skipping authentication
                    if (!cryptor.FileContentCryptor().CanSkipAuthentication())
                    {
                        continue;
                    }

                    // Setup test data
                    int size = 1 * 1024 * 1024; // 1MB
                    var cleartextBuffer = new byte[size];
                    var ciphertextBuffer = new byte[2 * size]; // Ciphertext is larger due to headers and authentication data
                    var resultBuffer = new byte[size + 1];

                    // Create streams for encryption/decryption
                    using (var cleartextStream = new MemoryStream(cleartextBuffer))
                    using (var ciphertextStream = new MemoryStream(ciphertextBuffer))
                    {
                        // Create encrypting stream wrapper
                        using (var encryptingStream = new EncryptingStream(ciphertextStream, cryptor))
                        {
                            // Encrypt data
                            cleartextStream.CopyTo(encryptingStream);
                            encryptingStream.Flush();
                        }

                        // Manipulate the ciphertext
                        int lastByteOfFirstChunk = cryptor.FileHeaderCryptor().HeaderSize() +
                            cryptor.FileContentCryptor().CiphertextChunkSize() - 1; // Inside chunk MAC
                        ciphertextBuffer[lastByteOfFirstChunk] = (byte)~ciphertextBuffer[lastByteOfFirstChunk];

                        // Reset ciphertext stream for reading
                        ciphertextStream.Position = 0;

                        // Create decrypting stream wrapper, skipping authentication
                        using (var decryptingStream = new DecryptingStream(ciphertextStream, cryptor, false))
                        using (var resultStream = new MemoryStream(resultBuffer))
                        {
                            // Decrypt data without authentication
                            decryptingStream.CopyTo(resultStream);
                        }

                        // Verify the decrypted data matches the original
                        for (int i = 0; i < size; i++)
                        {
                            Assert.AreEqual(cleartextBuffer[i], resultBuffer[i], $"Mismatch at position {i}");
                        }
                    }
                }
            }
        }
    }
}