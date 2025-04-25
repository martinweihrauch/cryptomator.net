using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using CryptomatorLib.Api;

namespace CryptomatorLib.Common
{
    /// <summary>
    /// Provides access to masterkey files, including reading, writing, and key derivation.
    /// </summary>
    public class MasterkeyFileAccess
    {
        private const int SCRYPT_COST_DEFAULT = 17; // 2^17 = 131072 iterations
        private const int SCRYPT_BLOCK_SIZE_DEFAULT = 8;
        private const int SCRYPT_PARALLELIZATION_DEFAULT = 1;
        
        private const int KEY_LEN_BYTES = 32;
        private const int MAC_LEN_BYTES = 32;
        private const int NONCE_LEN_BYTES = 16;
        
        /// <summary>
        /// Loads a masterkey file from disk.
        /// </summary>
        /// <param name="path">Path to the masterkey file</param>
        /// <returns>The loaded masterkey file</returns>
        /// <exception cref="IOException">If the file cannot be read</exception>
        public static MasterkeyFile Load(string path)
        {
            try
            {
                byte[] fileContent = File.ReadAllBytes(path);
                return MasterkeyFile.FromJson(fileContent);
            }
            catch (IOException ex)
            {
                throw new IOException($"Unable to read masterkey file: {path}", ex);
            }
            catch (Exception ex) when (ex is System.Text.Json.JsonException)
            {
                throw new IOException($"Invalid masterkey file format: {path}", ex);
            }
        }

        /// <summary>
        /// Saves a masterkey file to disk.
        /// </summary>
        /// <param name="masterkeyFile">The masterkey file to save</param>
        /// <param name="path">Path where to save the file</param>
        /// <exception cref="IOException">If the file cannot be written</exception>
        public static void Save(MasterkeyFile masterkeyFile, string path)
        {
            if (masterkeyFile == null)
            {
                throw new ArgumentNullException(nameof(masterkeyFile));
            }
            
            try
            {
                byte[] fileContent = masterkeyFile.ToJson();
                string? directory = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                File.WriteAllBytes(path, fileContent);
            }
            catch (IOException ex)
            {
                throw new IOException($"Unable to write masterkey file: {path}", ex);
            }
        }

        /// <summary>
        /// Creates a new masterkey file from a Cryptomator Vault Format master key.
        /// </summary>
        /// <param name="masterkey">The raw master key</param>
        /// <returns>A new masterkey file</returns>
        public static MasterkeyFile CreateNew(byte[] masterkey)
        {
            return CreateNew(masterkey, SCRYPT_COST_DEFAULT, SCRYPT_BLOCK_SIZE_DEFAULT, SCRYPT_PARALLELIZATION_DEFAULT);
        }

        /// <summary>
        /// Creates a new masterkey file from a Cryptomator Vault Format master key with custom parameters.
        /// </summary>
        /// <param name="masterkey">The raw master key</param>
        /// <param name="costParam">The scrypt cost parameter</param>
        /// <param name="blockSize">The scrypt block size</param>
        /// <param name="parallelism">The scrypt parallelism parameter</param>
        /// <returns>A new masterkey file</returns>
        public static MasterkeyFile CreateNew(byte[] masterkey, int costParam, int blockSize, int parallelism)
        {
            if (masterkey == null || masterkey.Length == 0)
            {
                throw new ArgumentException("Invalid master key", nameof(masterkey));
            }
            
            var masterkeyFile = new MasterkeyFile
            {
                ScryptCostParam = costParam,
                ScryptBlockSize = blockSize,
                ScryptParallelism = parallelism,
                VaultVersion = 8, // latest version of Cryptomator Vault Format
                ContentEncryptionScheme = "SIV_GCM", // default for version 8
                FilenameEncryptionScheme = "SIV", // default for version 8
            };

            return masterkeyFile;
        }

        /// <summary>
        /// Creates a masterkey file from a passphrase.
        /// </summary>
        /// <param name="passphrase">The passphrase</param>
        /// <returns>A masterkey file with encrypted key material</returns>
        public static MasterkeyFile CreateFromPassphrase(string passphrase)
        {
            return CreateFromPassphrase(passphrase, SCRYPT_COST_DEFAULT, SCRYPT_BLOCK_SIZE_DEFAULT, SCRYPT_PARALLELIZATION_DEFAULT);
        }

        /// <summary>
        /// Creates a masterkey file from a passphrase with custom parameters.
        /// </summary>
        /// <param name="passphrase">The passphrase</param>
        /// <param name="costParam">The scrypt cost parameter</param>
        /// <param name="blockSize">The scrypt block size</param>
        /// <param name="parallelism">The scrypt parallelism parameter</param>
        /// <returns>A masterkey file with encrypted key material</returns>
        public static MasterkeyFile CreateFromPassphrase(string passphrase, int costParam, int blockSize, int parallelism)
        {
            if (string.IsNullOrEmpty(passphrase))
            {
                throw new ArgumentException("Passphrase cannot be empty", nameof(passphrase));
            }
            
            // Generate random masterkey
            byte[] masterkey = new byte[KEY_LEN_BYTES];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(masterkey);
            }
            
            // Generate random nonce
            byte[] nonce = new byte[NONCE_LEN_BYTES];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonce);
            }
            
            var masterkeyFile = CreateNew(masterkey, costParam, blockSize, parallelism);
            
            try
            {
                // Derive key-encryption key from passphrase
                byte[] passphraseDerivedKey = DerivePassphraseKey(
                    Encoding.UTF8.GetBytes(passphrase),
                    nonce,
                    costParam,
                    blockSize,
                    parallelism);
                
                // Split derived key
                byte[] kek = new byte[KEY_LEN_BYTES];
                byte[] macKey = new byte[MAC_LEN_BYTES];
                
                Buffer.BlockCopy(passphraseDerivedKey, 0, kek, 0, KEY_LEN_BYTES);
                Buffer.BlockCopy(passphraseDerivedKey, KEY_LEN_BYTES, macKey, 0, MAC_LEN_BYTES);
                
                // Encrypt masterkey with kek
                byte[] encryptedMasterkey = EncryptMasterkey(masterkey, kek);
                
                // Calculate MAC
                byte[] mac = CalculateMac(macKey, encryptedMasterkey);
                
                // Store in masterkey file
                masterkeyFile.PrimaryMasterkey = Convert.ToBase64String(encryptedMasterkey);
                masterkeyFile.PrimaryMasterkeyNonce = Convert.ToBase64String(nonce);
                masterkeyFile.PrimaryMasterkeyMac = Convert.ToBase64String(mac);
                
                return masterkeyFile;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterkey);
            }
        }

        /// <summary>
        /// Loads the raw masterkey from a masterkey file using a passphrase.
        /// </summary>
        /// <param name="masterkeyFile">The masterkey file</param>
        /// <param name="passphrase">The passphrase</param>
        /// <returns>The raw masterkey</returns>
        /// <exception cref="InvalidPassphraseException">If the passphrase is incorrect</exception>
        public static byte[] LoadRawMasterkey(MasterkeyFile masterkeyFile, string passphrase)
        {
            if (masterkeyFile == null)
            {
                throw new ArgumentNullException(nameof(masterkeyFile));
            }
            if (string.IsNullOrEmpty(passphrase))
            {
                throw new ArgumentException("Passphrase cannot be empty", nameof(passphrase));
            }
            
            if (masterkeyFile.PrimaryMasterkey == null ||
                masterkeyFile.PrimaryMasterkeyNonce == null ||
                masterkeyFile.PrimaryMasterkeyMac == null)
            {
                throw new InvalidOperationException("Masterkey file does not contain a primary masterkey");
            }
            
            // Decode base64 values
            byte[] encryptedMasterkey = Convert.FromBase64String(masterkeyFile.PrimaryMasterkey);
            byte[] nonce = Convert.FromBase64String(masterkeyFile.PrimaryMasterkeyNonce);
            byte[] expectedMac = Convert.FromBase64String(masterkeyFile.PrimaryMasterkeyMac);
            
            // Derive key from passphrase
            byte[] passphraseDerivedKey = DerivePassphraseKey(
                Encoding.UTF8.GetBytes(passphrase),
                nonce,
                masterkeyFile.ScryptCostParam,
                masterkeyFile.ScryptBlockSize,
                masterkeyFile.ScryptParallelism);
            
            try
            {
                // Split derived key
                byte[] kek = new byte[KEY_LEN_BYTES];
                byte[] macKey = new byte[MAC_LEN_BYTES];
                
                Buffer.BlockCopy(passphraseDerivedKey, 0, kek, 0, KEY_LEN_BYTES);
                Buffer.BlockCopy(passphraseDerivedKey, KEY_LEN_BYTES, macKey, 0, MAC_LEN_BYTES);
                
                // Verify MAC
                byte[] calculatedMac = CalculateMac(macKey, encryptedMasterkey);
                
                if (!CryptographicOperations.FixedTimeEquals(expectedMac, calculatedMac))
                {
                    throw new InvalidPassphraseException("Incorrect passphrase");
                }
                
                // Decrypt masterkey
                return DecryptMasterkey(encryptedMasterkey, kek);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passphraseDerivedKey);
            }
        }

        private static byte[] DerivePassphraseKey(byte[] passphrase, byte[] salt, int costParam, int blockSize, int parallelism)
        {
            // We need a 64-byte (512-bit) key: 32 bytes for encryption, 32 bytes for authentication
            return Scrypt.DeriveKey(passphrase, salt, KEY_LEN_BYTES + MAC_LEN_BYTES, costParam, blockSize, parallelism);
        }

        private static byte[] EncryptMasterkey(byte[] masterkey, byte[] kek)
        {
            // Use AES key wrapping as specified in RFC 3394
            return AesKeyWrap.Wrap(kek, masterkey);
        }

        private static byte[] DecryptMasterkey(byte[] encryptedMasterkey, byte[] kek)
        {
            try
            {
                // Use AES key unwrapping as specified in RFC 3394
                return AesKeyWrap.Unwrap(kek, encryptedMasterkey);
            }
            catch (CryptographicException)
            {
                throw new InvalidPassphraseException("Incorrect passphrase");
            }
        }

        private static byte[] CalculateMac(byte[] macKey, byte[] data)
        {
            using (var hmac = new HMACSHA256(macKey))
            {
                return hmac.ComputeHash(data);
            }
        }
    }
} 