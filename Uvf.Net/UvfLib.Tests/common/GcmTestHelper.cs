using System;
using System.Security.Cryptography;

namespace UvfLib.Tests.Common
{
    /// <summary>
    /// Helper class for GCM-related tests.
    /// </summary>
    public static class GcmTestHelper
    {
        private static readonly Random RNG = new Random(42); // Seeded for predictability

        /// <summary>
        /// .NET's GCM implementation may have built-in IV-reuse protection. To bypass this for testing,
        /// we can re-initialize the cipher before running a test using randomized key-iv-pairs.
        /// </summary>
        /// <param name="cipherInitializer">A method that initializes a cipher with the given key and parameters</param>
        public static void Reset(CipherInitializer cipherInitializer)
        {
            byte[] keyBytes = new byte[16]; // 128-bit AES key
            byte[] nonceBytes = new byte[12]; // 96-bit nonce

            RNG.NextBytes(keyBytes);
            RNG.NextBytes(nonceBytes);

            var key = new byte[keyBytes.Length];
            Array.Copy(keyBytes, key, keyBytes.Length);

            var nonce = new byte[nonceBytes.Length];
            Array.Copy(nonceBytes, nonce, nonceBytes.Length);

            try
            {
                cipherInitializer(CipherMode.Encrypt, key, nonce);
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Failed to reset cipher", ex);
            }
        }

        /// <summary>
        /// Delegate for initializing a cipher.
        /// </summary>
        /// <param name="mode">The cipher mode (encrypt or decrypt)</param>
        /// <param name="key">The key material</param>
        /// <param name="nonce">The initialization vector/nonce</param>
        public delegate void CipherInitializer(CipherMode mode, byte[] key, byte[] nonce);

        /// <summary>
        /// Enumeration for cipher modes.
        /// </summary>
        public enum CipherMode
        {
            /// <summary>
            /// Encrypt mode.
            /// </summary>
            Encrypt,

            /// <summary>
            /// Decrypt mode.
            /// </summary>
            Decrypt
        }
    }
}