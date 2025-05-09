using System;
using System.Security.Cryptography;

namespace UvfLib.Tests.Common
{
    /// <summary>
    /// Mock implementation of AES-GCM cryptor for testing.
    /// </summary>
    public static class AesGcmCryptor
    {
        /// <summary>
        /// Encrypts data using AES-GCM.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="key">Encryption key</param>
        /// <param name="iv">Initialization vector</param>
        /// <returns>Encrypted data with authentication tag</returns>
        public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));
            
            // This is just a mock implementation that returns the original data for testing
            byte[] result = new byte[data.Length + 16]; // Add space for 16-byte auth tag
            Buffer.BlockCopy(data, 0, result, 0, data.Length);
            
            // Fill the auth tag with some deterministic value
            for (int i = 0; i < 16; i++)
            {
                result[data.Length + i] = (byte)(i ^ key[i % key.Length] ^ iv[i % iv.Length]);
            }
            
            return result;
        }
        
        /// <summary>
        /// Decrypts data using AES-GCM.
        /// </summary>
        /// <param name="data">Data with authentication tag to decrypt</param>
        /// <param name="key">Encryption key</param>
        /// <param name="iv">Initialization vector</param>
        /// <returns>Decrypted data</returns>
        public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (iv == null) throw new ArgumentNullException(nameof(iv));
            
            if (data.Length < 16)
            {
                throw new CryptographicException("Data is too short to contain authentication tag");
            }
            
            // This is just a mock implementation that returns the original data for testing
            byte[] result = new byte[data.Length - 16]; // Remove 16-byte auth tag
            Buffer.BlockCopy(data, 0, result, 0, result.Length);
            
            return result;
        }
    }
    
    /// <summary>
    /// Mock implementation of AES-CTR cryptor for testing.
    /// </summary>
    public static class AesCtrCryptor
    {
        /// <summary>
        /// Encrypts data using AES-CTR.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="key">Encryption key</param>
        /// <param name="counter">Counter block</param>
        /// <returns>Encrypted data</returns>
        public static byte[] Encrypt(byte[] data, byte[] key, byte[] counter)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (counter == null) throw new ArgumentNullException(nameof(counter));
            
            // This is just a mock implementation that returns the original data for testing
            byte[] result = new byte[data.Length];
            Buffer.BlockCopy(data, 0, result, 0, data.Length);
            
            return result;
        }
        
        /// <summary>
        /// Decrypts data using AES-CTR.
        /// </summary>
        /// <param name="data">Data to decrypt</param>
        /// <param name="key">Encryption key</param>
        /// <param name="counter">Counter block</param>
        /// <returns>Decrypted data</returns>
        public static byte[] Decrypt(byte[] data, byte[] key, byte[] counter)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (counter == null) throw new ArgumentNullException(nameof(counter));
            
            // For CTR mode, encryption and decryption are the same operation
            return Encrypt(data, key, counter);
        }
    }
} 