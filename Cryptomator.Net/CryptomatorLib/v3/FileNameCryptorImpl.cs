using System;
using System.Security.Cryptography;
using System.Text;
using CryptomatorLib.Api;
using CryptomatorLib.Common;

namespace CryptomatorLib.V3
{
    /// <summary>
    /// Implementation of the FileNameCryptor interface for v3 format.
    /// </summary>
    internal sealed class FileNameCryptorImpl : FileNameCryptor
    {
        private const string CIPHERTEXT_SEPARATOR = "_";
        private static readonly byte[] KDF_CONTEXT = Encoding.ASCII.GetBytes("fileNames");
        private static readonly byte[] DIR_HASH_KDF_CONTEXT = Encoding.ASCII.GetBytes("directoryId");

        private readonly RevolvingMasterkey _masterkey;
        private readonly RandomNumberGenerator _random;

        /// <summary>
        /// Creates a new file name cryptor.
        /// </summary>
        /// <param name="masterkey">The revolving masterkey</param>
        /// <param name="random">The random number generator</param>
        internal FileNameCryptorImpl(RevolvingMasterkey masterkey, RandomNumberGenerator random)
        {
            _masterkey = masterkey ?? throw new ArgumentNullException(nameof(masterkey));
            _random = random ?? throw new ArgumentNullException(nameof(random));
        }

        /// <summary>
        /// Encrypts a directory ID.
        /// </summary>
        /// <param name="cleartextDirectoryId">The cleartext directory ID</param>
        /// <returns>The encrypted directory ID</returns>
        public string EncryptDirectoryId(string cleartextDirectoryId)
        {
            if (string.IsNullOrEmpty(cleartextDirectoryId))
            {
                throw new ArgumentException("Directory ID must not be empty", nameof(cleartextDirectoryId));
            }

            return EncryptFilename(cleartextDirectoryId);
        }

        /// <summary>
        /// Decrypts a directory ID.
        /// </summary>
        /// <param name="ciphertextDirectoryId">The encrypted directory ID</param>
        /// <returns>The cleartext directory ID</returns>
        public string DecryptDirectoryId(string ciphertextDirectoryId)
        {
            if (string.IsNullOrEmpty(ciphertextDirectoryId))
            {
                throw new ArgumentException("Directory ID must not be empty", nameof(ciphertextDirectoryId));
            }

            return DecryptFilename(ciphertextDirectoryId);
        }

        /// <summary>
        /// Encrypts a file name.
        /// </summary>
        /// <param name="cleartextName">The cleartext file name</param>
        /// <returns>The encrypted file name</returns>
        public string EncryptFilename(string cleartextName)
        {
            if (string.IsNullOrEmpty(cleartextName))
            {
                throw new ArgumentException("File name must not be empty", nameof(cleartextName));
            }

            // Get bytes of cleartext name using UTF-8
            byte[] cleartextBytes = Encoding.UTF8.GetBytes(cleartextName);

            // Generate random nonce
            byte[] nonce = new byte[Constants.GCM_NONCE_SIZE];
            _random.GetBytes(nonce);

            // Derive encryption key from masterkey
            try
            {
                using var nameKey = DeriveNameKey(_masterkey.Current());
                using var aesGcm = new AesGcm(nameKey.GetRaw());

                // Encrypt data
                byte[] ciphertext = new byte[cleartextBytes.Length];
                byte[] tag = new byte[Constants.GCM_TAG_SIZE];
                aesGcm.Encrypt(nonce, cleartextBytes, ciphertext, tag, Array.Empty<byte>());

                // Construct result: <seedId>_<nonce+ciphertext+tag base64>
                string seedId = _masterkey.Current().ToString();
                string base64 = Convert.ToBase64String(ByteBuffers.Concat(nonce, ciphertext, tag))
                    .Replace('/', '_')
                    .Replace('+', '-')
                    .Replace("=", "");

                return seedId + CIPHERTEXT_SEPARATOR + base64;
            }
            catch (CryptographicException ex)
            {
                throw new CryptoException("Failed to encrypt file name", ex);
            }
            finally
            {
                CryptomatorLib.Common.CryptographicOperations.ZeroMemory(cleartextBytes);
                CryptomatorLib.Common.CryptographicOperations.ZeroMemory(nonce);
            }
        }

        /// <summary>
        /// Encrypts a file name with a specific prefix.
        /// </summary>
        /// <param name="cleartextName">The cleartext file name</param>
        /// <param name="prefix">Custom prefix for the resulting encrypted file name</param>
        /// <returns>The encrypted file name</returns>
        public string EncryptFilename(string cleartextName, string prefix)
        {
            if (string.IsNullOrEmpty(cleartextName))
            {
                throw new ArgumentException("File name must not be empty", nameof(cleartextName));
            }
            if (prefix == null)
            {
                throw new ArgumentNullException(nameof(prefix));
            }

            // For UVF format, prefix is not used, but we could implement it as needed
            return prefix + EncryptFilename(cleartextName);
        }

        /// <summary>
        /// Encrypts a file name for a specific directory.
        /// </summary>
        /// <param name="cleartextName">The cleartext file name</param>
        /// <param name="dirId">The directory ID</param>
        /// <returns>The encrypted file name</returns>
        public string EncryptFilename(string cleartextName, byte[] dirId)
        {
            // In this implementation, we don't use the dirId for encryption
            // but add the .uvf extension as required by the format
            if (string.IsNullOrEmpty(cleartextName))
            {
                throw new ArgumentException("File name must not be empty", nameof(cleartextName));
            }
            if (dirId == null)
            {
                throw new ArgumentNullException(nameof(dirId));
            }

            string ciphertext = EncryptFilename(cleartextName);
            return ciphertext + Constants.UVF_FILE_EXT;
        }

        /// <summary>
        /// Decrypts a file name from a specific directory.
        /// </summary>
        /// <param name="ciphertextName">The encrypted file name</param>
        /// <param name="dirId">The directory ID</param>
        /// <returns>The cleartext file name</returns>
        public string DecryptFilename(string ciphertextName, byte[] dirId)
        {
            if (string.IsNullOrEmpty(ciphertextName))
            {
                throw new ArgumentException("File name must not be empty", nameof(ciphertextName));
            }
            if (dirId == null)
            {
                throw new ArgumentNullException(nameof(dirId));
            }

            // Remove the .uvf extension
            if (!ciphertextName.EndsWith(Constants.UVF_FILE_EXT))
            {
                throw new ArgumentException($"Not a {Constants.UVF_FILE_EXT} file: {ciphertextName}", nameof(ciphertextName));
            }

            string ciphertextWithoutExt = ciphertextName.Substring(0, ciphertextName.Length - Constants.UVF_FILE_EXT.Length);

            // Decrypt the filename
            return DecryptFilename(ciphertextWithoutExt);
        }

        /// <summary>
        /// Decrypts a file name.
        /// </summary>
        /// <param name="ciphertextName">The encrypted file name</param>
        /// <returns>The cleartext file name</returns>
        public string DecryptFilename(string ciphertextName)
        {
            if (string.IsNullOrEmpty(ciphertextName))
            {
                throw new ArgumentException("File name must not be empty", nameof(ciphertextName));
            }

            // Parse the ciphertext name
            int separatorIndex = ciphertextName.IndexOf(CIPHERTEXT_SEPARATOR);
            if (separatorIndex == -1 || separatorIndex == 0 || separatorIndex == ciphertextName.Length - 1)
            {
                throw new InvalidCiphertextException("Invalid ciphertext format");
            }

            string seedId = ciphertextName.Substring(0, separatorIndex);
            string encodedPayload = ciphertextName.Substring(separatorIndex + 1)
                .Replace('_', '/')
                .Replace('-', '+');

            // Add padding for Base64 if needed
            switch (encodedPayload.Length % 4)
            {
                case 2: encodedPayload += "=="; break;
                case 3: encodedPayload += "="; break;
            }

            // Decode Base64 payload
            byte[] payload;
            try
            {
                payload = Convert.FromBase64String(encodedPayload);
            }
            catch (FormatException ex)
            {
                throw new InvalidCiphertextException("Invalid Base64 encoding", ex);
            }

            // Validate payload length
            if (payload.Length < Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE)
            {
                throw new InvalidCiphertextException("Payload too short");
            }

            // Extract components
            byte[] nonce = new byte[Constants.GCM_NONCE_SIZE];
            Array.Copy(payload, 0, nonce, 0, Constants.GCM_NONCE_SIZE);

            int ciphertextLength = payload.Length - Constants.GCM_NONCE_SIZE - Constants.GCM_TAG_SIZE;
            byte[] ciphertext = new byte[ciphertextLength];
            Array.Copy(payload, Constants.GCM_NONCE_SIZE, ciphertext, 0, ciphertextLength);

            byte[] tag = new byte[Constants.GCM_TAG_SIZE];
            Array.Copy(payload, Constants.GCM_NONCE_SIZE + ciphertextLength, tag, 0, Constants.GCM_TAG_SIZE);

            // Get masterkey for the given seed ID
            DestroyableMasterkey masterkey;
            try
            {
                // Get the masterkey by seed ID (implementation would depend on your masterkey lookup system)
                masterkey = _masterkey.GetBySeedId(seedId);
            }
            catch (Exception ex)
            {
                throw new InvalidCiphertextException($"No masterkey with seed ID {seedId} available", ex);
            }

            // Decrypt
            try
            {
                using var nameKey = DeriveNameKey(masterkey);
                using var aesGcm = new AesGcm(nameKey.GetRaw());

                byte[] cleartextBytes = new byte[ciphertextLength];
                try
                {
                    aesGcm.Decrypt(nonce, ciphertext, tag, cleartextBytes, Array.Empty<byte>());
                }
                catch (CryptographicException ex)
                {
                    throw new AuthenticationFailedException("Failed to authenticate file name", ex);
                }

                return Encoding.UTF8.GetString(cleartextBytes);
            }
            catch (CryptographicException ex)
            {
                throw new CryptoException("Failed to decrypt file name", ex);
            }
            finally
            {
                CryptomatorLib.Common.CryptographicOperations.ZeroMemory(nonce);
                CryptomatorLib.Common.CryptographicOperations.ZeroMemory(payload);
            }
        }

        private DestroyableSecretKey DeriveNameKey(DestroyableMasterkey masterkey)
        {
            byte[] masterkeyBytes = masterkey.GetRawKey();
            byte[] nameKey = new byte[32]; // AES-256

            try
            {
                // Use HKDF to derive the name key
                HKDFHelper.HkdfSha256(null, masterkeyBytes, nameKey, KDF_CONTEXT);

                return new DestroyableSecretKey(nameKey, "AES");
            }
            catch (Exception ex)
            {
                CryptomatorLib.Common.CryptographicOperations.ZeroMemory(nameKey);
                throw new CryptoException("Failed to derive name key", ex);
            }
            finally
            {
                CryptomatorLib.Common.CryptographicOperations.ZeroMemory(masterkeyBytes);
            }
        }

        /// <summary>
        /// Hashes a directory ID for use in path construction.
        /// </summary>
        /// <param name="dirId">The directory ID to hash</param>
        /// <returns>The hashed directory ID as a Base32 string</returns>
        public string HashDirectoryId(byte[] dirId)
        {
            if (dirId == null)
                throw new ArgumentNullException(nameof(dirId));

            // Use HMAC-SHA256 for hashing with a key derived from the master key
            using var key = _masterkey.SubKey(_masterkey.GetFirstRevision(), 32, DIR_HASH_KDF_CONTEXT, "HMAC-SHA256");

            using var hmac = new HMACSHA256(key.GetRaw());
            byte[] hash = hmac.ComputeHash(dirId);

            // Convert to uppercase Base32 string
            return Base32Encoding.ToString(hash).ToUpperInvariant();
        }
    }

    /// <summary>
    /// Base32 Encoding Implementation (RFC 4648)
    /// </summary>
    internal static class Base32Encoding
    {
        private static readonly char[] DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();

        /// <summary>
        /// Converts a byte array to a Base32 string
        /// </summary>
        /// <param name="data">The data to encode</param>
        /// <returns>The Base32 encoded string</returns>
        public static string ToString(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            StringBuilder result = new StringBuilder((data.Length * 8 + 4) / 5);

            int buffer = 0;
            int next = 0;
            int bitsLeft = 0;

            foreach (byte b in data)
            {
                buffer <<= 8;
                buffer |= b & 0xFF;
                bitsLeft += 8;

                while (bitsLeft >= 5)
                {
                    bitsLeft -= 5;
                    result.Append(DIGITS[(buffer >> bitsLeft) & 0x1F]);
                }
            }

            if (bitsLeft > 0)
            {
                buffer <<= (5 - bitsLeft);
                result.Append(DIGITS[buffer & 0x1F]);
            }

            return result.ToString();
        }
    }
}