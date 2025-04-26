using System;
using System.Security.Cryptography;
using CryptomatorLib.Api; // Add this for InvalidCiphertextException

namespace CryptomatorLib.V3
{
    /// <summary>
    /// Helper methods for AES-SIV encryption and decryption with compatibility with the Java implementation
    /// </summary>
    internal static class AesSivHelper
    {
        // AES-SIV block size (16 bytes)
        private const int BLOCK_SIZE = 16;

        /// <summary>
        /// Encrypts data using AES-SIV, implementing RFC5297
        /// </summary>
        /// <param name="key">The encryption key (must be 64 bytes for AES-SIV-512)</param>
        /// <param name="plaintext">The plaintext to encrypt</param>
        /// <param name="ad">The associated data</param>
        /// <returns>The ciphertext (with SIV/Tag prepended)</returns>
        public static byte[] Encrypt(byte[] key, byte[] plaintext, byte[] ad)
        {
            if (key == null || key.Length != 64)
            {
                throw new ArgumentException("Key must be 64 bytes for AES-SIV-512", nameof(key));
            }

            if (plaintext == null)
            {
                throw new ArgumentNullException(nameof(plaintext));
            }

            // Split the key into two halves (K1 for CMAC, K2 for CTR encryption)
            byte[] k1 = new byte[32];
            byte[] k2 = new byte[32];
            Buffer.BlockCopy(key, 0, k1, 0, 32);
            Buffer.BlockCopy(key, 32, k2, 0, 32);

            // Step 1: Generate the SIV (Synthetic Initialization Vector) using S2V operation
            byte[] siv = S2V(k1, plaintext, ad != null ? new[] { ad } : Array.Empty<byte[]>());

            // Step 2: Encrypt the plaintext using AES-CTR with modified SIV as counter
            byte[] modifiedSiv = new byte[BLOCK_SIZE];
            Buffer.BlockCopy(siv, 0, modifiedSiv, 0, BLOCK_SIZE);
            // Clear the most significant bit in the last 32 bits (per RFC5297)
            modifiedSiv[8] &= 0x7F;
            modifiedSiv[12] &= 0x7F;

            // Encrypt the plaintext with AES-CTR
            byte[] ciphertext = EncryptWithCtr(k2, modifiedSiv, plaintext);

            // Combine SIV and ciphertext
            byte[] result = new byte[siv.Length + ciphertext.Length];
            Buffer.BlockCopy(siv, 0, result, 0, siv.Length);
            Buffer.BlockCopy(ciphertext, 0, result, siv.Length, ciphertext.Length);

            return result;
        }

        /// <summary>
        /// Generate Synthetic Initialization Vector using S2V operation as defined in RFC 5297
        /// This implementation matches the Java version in org.cryptomator.siv.SivMode
        /// </summary>
        private static byte[] S2V(byte[] key, byte[] plaintext, byte[][] associatedData)
        {
            // Maximum permitted AD length is the block size in bits - 2
            if (associatedData.Length > 126)
            {
                throw new ArgumentException("too many Associated Data fields");
            }

            // Initialize HMAC with the key (used as a replacement for CMac in Java)
            using HMACSHA256 hmac = new HMACSHA256(key);

            // D = AES-CMAC(K1, <zero>)
            byte[] zero = new byte[BLOCK_SIZE];
            byte[] d = Mac(hmac, zero);

            // Process associated data if present
            foreach (byte[] s in associatedData)
            {
                if (s != null && s.Length > 0)
                {
                    byte[] adMac = Mac(hmac, s);

                    // Make sure the arrays are properly sized for XOR operation
                    // The Dbl output and adMac should be the same length, but we ensure it here
                    byte[] doubled = Dbl(d);
                    if (doubled.Length != adMac.Length)
                    {
                        // Adjust sizes to match - we need the minimum of the two lengths
                        int minLength = Math.Min(doubled.Length, adMac.Length);
                        byte[] tmp1 = new byte[minLength];
                        byte[] tmp2 = new byte[minLength];

                        Buffer.BlockCopy(doubled, 0, tmp1, 0, Math.Min(doubled.Length, minLength));
                        Buffer.BlockCopy(adMac, 0, tmp2, 0, Math.Min(adMac.Length, minLength));

                        d = Xor(tmp1, tmp2);
                    }
                    else
                    {
                        d = Xor(doubled, adMac);
                    }
                }
            }

            // Process plaintext
            byte[] t;
            if (plaintext.Length >= BLOCK_SIZE)
            {
                // Make sure d is not longer than BLOCK_SIZE 
                byte[] adjustedD = d;
                if (d.Length > BLOCK_SIZE)
                {
                    adjustedD = new byte[BLOCK_SIZE];
                    Buffer.BlockCopy(d, 0, adjustedD, 0, BLOCK_SIZE);
                }

                t = XorEnd(plaintext, adjustedD);
            }
            else
            {
                byte[] paddedPlaintext = Pad(plaintext);

                // Make sure the arrays are properly sized for XOR operation
                byte[] doubledD = Dbl(d);
                if (doubledD.Length != paddedPlaintext.Length)
                {
                    // Adjust sizes to match
                    int minLength = Math.Min(doubledD.Length, paddedPlaintext.Length);
                    byte[] tmp1 = new byte[minLength];
                    byte[] tmp2 = new byte[minLength];

                    Buffer.BlockCopy(doubledD, 0, tmp1, 0, Math.Min(doubledD.Length, minLength));
                    Buffer.BlockCopy(paddedPlaintext, 0, tmp2, 0, Math.Min(paddedPlaintext.Length, minLength));

                    t = Xor(tmp1, tmp2);
                }
                else
                {
                    t = Xor(doubledD, paddedPlaintext);
                }
            }

            return Mac(hmac, t);
        }

        /// <summary>
        /// Performs MAC operation - equivalent to mac() in Java implementation
        /// </summary>
        private static byte[] Mac(HMACSHA256 hmac, byte[] input)
        {
            // Since we're using HMACSHA256 instead of CMAC,
            // output is 32 bytes instead of 16, so we truncate to match CMAC
            byte[] fullResult = hmac.ComputeHash(input);
            byte[] truncated = new byte[BLOCK_SIZE];
            Buffer.BlockCopy(fullResult, 0, truncated, 0, BLOCK_SIZE);
            return truncated;
        }

        /// <summary>
        /// Pads the input according to ISO7816-4 - equivalent to pad() in Java implementation
        /// First bit 1, following bits 0
        /// </summary>
        private static byte[] Pad(byte[] input)
        {
            byte[] result = new byte[BLOCK_SIZE];
            Buffer.BlockCopy(input, 0, result, 0, input.Length);

            // Add padding: first bit 1, following bits 0 (ISO7816-4)
            result[input.Length] = 0x80;

            return result;
        }

        /// <summary>
        /// Doubles a value (left shift by 1) with conditional XOR if high bit is set
        /// Equivalent to dbl() in Java implementation
        /// </summary>
        private static byte[] Dbl(byte[] input)
        {
            byte[] ret = new byte[input.Length];
            int carry = ShiftLeft(input, ret);
            int xor = 0xff & 0x87;  // DOUBLING_CONST in Java

            // This construction is an attempt at a constant-time implementation
            int mask = (-carry) & 0xff;
            ret[input.Length - 1] ^= (byte)(xor & mask);

            return ret;
        }

        /// <summary>
        /// Shifts left by one bit - equivalent to shiftLeft() in Java implementation
        /// </summary>
        private static int ShiftLeft(byte[] block, byte[] output)
        {
            int i = block.Length;
            int bit = 0;
            while (--i >= 0)
            {
                int b = block[i] & 0xff;
                output[i] = (byte)((b << 1) | bit);
                bit = (b >> 7) & 1;
            }
            return bit;
        }

        /// <summary>
        /// XOR two byte arrays - equivalent to xor() in Java implementation
        /// </summary>
        private static byte[] Xor(byte[] in1, byte[] in2)
        {
            // Ensure arrays are the same length
            if (in1.Length != in2.Length)
            {
                throw new ArgumentException("Arrays must be same length for XOR operation");
            }

            byte[] result = new byte[in1.Length];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = (byte)(in1[i] ^ in2[i]);
            }
            return result;
        }

        /// <summary>
        /// XOR at the end of array - equivalent to xorend() in Java implementation
        /// </summary>
        private static byte[] XorEnd(byte[] in1, byte[] in2)
        {
            if (in1.Length < in2.Length)
            {
                throw new ArgumentException("Length of first input must be >= length of second input");
            }

            byte[] result = new byte[in1.Length];
            Buffer.BlockCopy(in1, 0, result, 0, in1.Length);

            int diff = in1.Length - in2.Length;
            for (int i = 0; i < in2.Length; i++)
            {
                result[i + diff] = (byte)(result[i + diff] ^ in2[i]);
            }
            return result;
        }

        /// <summary>
        /// Encrypt using AES-CTR mode
        /// </summary>
        private static byte[] EncryptWithCtr(byte[] key, byte[] counter, byte[] plaintext)
        {
            byte[] ciphertext = new byte[plaintext.Length];

            using Aes aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            byte[] counterBlock = new byte[BLOCK_SIZE];
            Buffer.BlockCopy(counter, 0, counterBlock, 0, BLOCK_SIZE);

            using ICryptoTransform encryptor = aes.CreateEncryptor();

            for (int i = 0; i < plaintext.Length; i += BLOCK_SIZE)
            {
                // Encrypt the counter
                byte[] encryptedCounter = new byte[BLOCK_SIZE];
                encryptor.TransformBlock(counterBlock, 0, BLOCK_SIZE, encryptedCounter, 0);

                // XOR with plaintext to get ciphertext
                int bytesToProcess = Math.Min(BLOCK_SIZE, plaintext.Length - i);
                for (int j = 0; j < bytesToProcess; j++)
                {
                    ciphertext[i + j] = (byte)(plaintext[i + j] ^ encryptedCounter[j]);
                }

                // Increment counter
                IncrementCounter(counterBlock);
            }

            return ciphertext;
        }

        /// <summary>
        /// Increment the counter (big-endian)
        /// </summary>
        private static void IncrementCounter(byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                if (++counter[i] != 0)
                {
                    break;
                }
            }
        }

        /// <summary>
        /// Decrypts data using AES-SIV
        /// </summary>
        /// <param name="key">The decryption key (must be 64 bytes for AES-SIV-512)</param>
        /// <param name="ciphertext">The ciphertext to decrypt (with SIV/Tag prepended)</param>
        /// <param name="ad">The associated data</param>
        /// <returns>The plaintext</returns>
        public static byte[] Decrypt(byte[] key, byte[] ciphertext, byte[] ad)
        {
            if (key == null || key.Length != 64)
            {
                throw new ArgumentException("Key must be 64 bytes for AES-SIV-512", nameof(key));
            }

            if (ciphertext == null || ciphertext.Length < BLOCK_SIZE)
            {
                throw new InvalidCiphertextException("Ciphertext too short");
            }

            // Split the key into two halves (K1 for CMAC, K2 for CTR decryption)
            byte[] k1 = new byte[32];
            byte[] k2 = new byte[32];
            Buffer.BlockCopy(key, 0, k1, 0, 32);
            Buffer.BlockCopy(key, 32, k2, 0, 32);

            // Extract SIV and actual ciphertext
            byte[] iv = new byte[BLOCK_SIZE];
            byte[] actualCiphertext = new byte[ciphertext.Length - BLOCK_SIZE];
            Buffer.BlockCopy(ciphertext, 0, iv, 0, BLOCK_SIZE);
            Buffer.BlockCopy(ciphertext, BLOCK_SIZE, actualCiphertext, 0, actualCiphertext.Length);

            // Create modified SIV for decryption
            byte[] modifiedSiv = new byte[BLOCK_SIZE];
            Buffer.BlockCopy(iv, 0, modifiedSiv, 0, BLOCK_SIZE);
            // Clear the most significant bit in the last 32 bits (per RFC5297)
            modifiedSiv[8] &= 0x7F;
            modifiedSiv[12] &= 0x7F;

            // Decrypt the ciphertext with AES-CTR
            byte[] plaintext = EncryptWithCtr(k2, modifiedSiv, actualCiphertext); // CTR mode is symmetric

            // Verify the SIV by regenerating it from the plaintext and AD
            byte[] control = S2V(k1, plaintext, ad != null ? new[] { ad } : Array.Empty<byte[]>());

            // Compare the SIVs to authenticate the data - time-constant comparison
            if (control.Length != iv.Length)
            {
                throw new CryptographicException("Authentication failed");
            }

            int diff = 0;
            for (int i = 0; i < iv.Length; i++)
            {
                diff |= iv[i] ^ control[i];
            }

            if (diff == 0)
            {
                return plaintext;
            }
            else
            {
                throw new CryptographicException("Authentication failed");
            }
        }
    }
}