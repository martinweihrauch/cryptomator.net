using System;
using System.Security.Cryptography;

namespace CryptomatorLib.Common
{
    /// <summary>
    /// Implementation of the AES Key Wrap algorithm as specified in RFC 3394.
    /// </summary>
    public static class AesKeyWrap
    {
        /// <summary>
        /// Default IV value for AES Key Wrap algorithm as specified in RFC 3394.
        /// </summary>
        private static readonly byte[] DEFAULT_IV = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };

        /// <summary>
        /// Wraps a key using the AES Key Wrap algorithm.
        /// </summary>
        /// <param name="kek">The Key Encryption Key (KEK)</param>
        /// <param name="keyToWrap">The key to wrap</param>
        /// <returns>The wrapped key</returns>
        /// <exception cref="ArgumentNullException">If kek or keyToWrap is null</exception>
        /// <exception cref="ArgumentException">If keyToWrap length is not a multiple of 8 bytes</exception>
        public static byte[] Wrap(byte[] kek, byte[] keyToWrap)
        {
            if (kek == null)
            {
                throw new ArgumentNullException(nameof(kek));
            }
            if (keyToWrap == null)
            {
                throw new ArgumentNullException(nameof(keyToWrap));
            }
            if (keyToWrap.Length % 8 != 0)
            {
                throw new ArgumentException("Key to wrap must be a multiple of 8 bytes", nameof(keyToWrap));
            }

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = kek;

                return WrapCore(aes, DEFAULT_IV, keyToWrap);
            }
        }

        /// <summary>
        /// Unwraps a key using the AES Key Wrap algorithm.
        /// </summary>
        /// <param name="kek">The Key Encryption Key (KEK)</param>
        /// <param name="wrappedKey">The wrapped key</param>
        /// <returns>The unwrapped key</returns>
        /// <exception cref="ArgumentNullException">If kek or wrappedKey is null</exception>
        /// <exception cref="ArgumentException">If wrappedKey length is not at least 16 bytes or not a multiple of 8 bytes</exception>
        /// <exception cref="CryptographicException">If key unwrapping fails due to integrity check failure</exception>
        public static byte[] Unwrap(byte[] kek, byte[] wrappedKey)
        {
            if (kek == null)
            {
                throw new ArgumentNullException(nameof(kek));
            }
            if (wrappedKey == null)
            {
                throw new ArgumentNullException(nameof(wrappedKey));
            }
            if (wrappedKey.Length < 16 || wrappedKey.Length % 8 != 0)
            {
                throw new ArgumentException("Wrapped key must be at least 16 bytes and a multiple of 8 bytes", nameof(wrappedKey));
            }

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = kek;

                return UnwrapCore(aes, DEFAULT_IV, wrappedKey);
            }
        }

        private static byte[] WrapCore(Aes aes, byte[] iv, byte[] keyToWrap)
        {
            // Number of 64-bit blocks in the key to wrap
            int n = keyToWrap.Length / 8;

            // Initialize variables
            byte[] a = new byte[8]; // A
            byte[] r = new byte[keyToWrap.Length + 8]; // Output buffer

            // Set initial values
            Buffer.BlockCopy(iv, 0, a, 0, 8);
            Buffer.BlockCopy(keyToWrap, 0, r, 8, keyToWrap.Length);

            // Create encryptor
            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            {
                byte[] block = new byte[16]; // Temporary block for encryption

                // Main wrapping loop
                for (int j = 0; j <= 5; j++)
                {
                    for (int i = 1; i <= n; i++)
                    {
                        // Construct the block to encrypt (A | R[i])
                        Buffer.BlockCopy(a, 0, block, 0, 8);
                        Buffer.BlockCopy(r, i * 8, block, 8, 8);

                        // Encrypt
                        encryptor.TransformBlock(block, 0, 16, block, 0);

                        // Update A with the first 8 bytes of the encrypted block
                        Buffer.BlockCopy(block, 0, a, 0, 8);

                        // Update counter by XORing with big-endian value of (n*j)+i
                        int t = n * j + i;
                        for (int k = 7; t != 0 && k >= 0; k--)
                        {
                            a[k] ^= (byte)(t & 0xFF);
                            t >>= 8;
                        }

                        // Store the last 8 bytes of the encrypted block in R[i]
                        Buffer.BlockCopy(block, 8, r, i * 8, 8);
                    }
                }
            }

            // Prepend A to the wrapped key
            Buffer.BlockCopy(a, 0, r, 0, 8);

            return r;
        }

        private static byte[] UnwrapCore(Aes aes, byte[] iv, byte[] wrappedKey)
        {
            // Number of 64-bit blocks in the wrapped key (excluding A)
            int n = (wrappedKey.Length / 8) - 1;

            // Initialize variables
            byte[] a = new byte[8]; // A
            byte[] r = new byte[wrappedKey.Length - 8]; // Output buffer

            // Set initial values
            Buffer.BlockCopy(wrappedKey, 0, a, 0, 8);
            Buffer.BlockCopy(wrappedKey, 8, r, 0, wrappedKey.Length - 8);

            // Create decryptor
            using (ICryptoTransform decryptor = aes.CreateDecryptor())
            {
                byte[] block = new byte[16]; // Temporary block for decryption

                // Main unwrapping loop
                for (int j = 5; j >= 0; j--)
                {
                    for (int i = n; i >= 1; i--)
                    {
                        // Update counter by XORing with big-endian value of (n*j)+i
                        int t = n * j + i;
                        for (int k = 7; t != 0 && k >= 0; k--)
                        {
                            a[k] ^= (byte)(t & 0xFF);
                            t >>= 8;
                        }

                        // Construct the block to decrypt (A | R[i])
                        Buffer.BlockCopy(a, 0, block, 0, 8);
                        Buffer.BlockCopy(r, (i - 1) * 8, block, 8, 8);

                        // Decrypt
                        decryptor.TransformBlock(block, 0, 16, block, 0);

                        // Update A with the first 8 bytes of the decrypted block
                        Buffer.BlockCopy(block, 0, a, 0, 8);

                        // Store the last 8 bytes of the decrypted block in R[i]
                        Buffer.BlockCopy(block, 8, r, (i - 1) * 8, 8);
                    }
                }
            }

            // Verify integrity
            for (int i = 0; i < 8; i++)
            {
                if (a[i] != iv[i])
                {
                    throw new CryptographicException("Key unwrap integrity check failed");
                }
            }

            return r;
        }
    }
} 