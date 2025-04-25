using System;
using System.Security.Cryptography;

namespace CryptomatorLib.Common
{
    /// <summary>
    /// Implementation of the scrypt key derivation function.
    /// </summary>
    public static class Scrypt
    {
        // Constants for scrypt
        private const int BLOCK_SIZE = 8;
        private const int DEFAULT_LOG_N = 17; // 2^17 = 131,072
        private const int DEFAULT_R = 8;
        private const int DEFAULT_P = 1;

        /// <summary>
        /// Derives a key using the scrypt algorithm with default parameters.
        /// </summary>
        /// <param name="password">The password to derive from</param>
        /// <param name="salt">The salt</param>
        /// <param name="dkLen">The desired key length</param>
        /// <returns>The derived key</returns>
        public static byte[] DeriveKey(byte[] password, byte[] salt, int dkLen)
        {
            return DeriveKey(password, salt, dkLen, DEFAULT_LOG_N, DEFAULT_R, DEFAULT_P);
        }

        /// <summary>
        /// Derives a key using the scrypt algorithm with custom parameters.
        /// </summary>
        /// <param name="password">The password to derive from</param>
        /// <param name="salt">The salt</param>
        /// <param name="dkLen">The desired key length</param>
        /// <param name="logN">The base-2 logarithm of the CPU/memory cost parameter (N)</param>
        /// <param name="r">The block size parameter</param>
        /// <param name="p">The parallelization parameter</param>
        /// <returns>The derived key</returns>
        public static byte[] DeriveKey(byte[] password, byte[] salt, int dkLen, int logN, int r, int p)
        {
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            if (salt == null)
            {
                throw new ArgumentNullException(nameof(salt));
            }
            if (dkLen <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(dkLen), "Key length must be positive");
            }
            if (logN < 1 || logN > 30)
            {
                throw new ArgumentOutOfRangeException(nameof(logN), "Log N must be between 1 and 30");
            }
            if (r <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(r), "r must be positive");
            }
            if (p <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(p), "p must be positive");
            }
            
            int N = 1 << logN;
            
            // Compute MFLen
            long mfLen = 128 * r * N; // in bytes
            
            // CPU/memory cost constraint
            if (mfLen > (int.MaxValue - 1024))
            {
                throw new ArgumentException("Parameters too large");
            }
            
            // Compute B = PBKDF2(password, salt, 1, p * 128 * r)
            byte[] B = PBKDF2_SHA256(password, salt, 1, p * 128 * r);
            
            // Compute B' = SMix(B)
            SMix(B, N, r, p);
            
            // Compute DK = PBKDF2(password, B', 1, dkLen)
            return PBKDF2_SHA256(password, B, 1, dkLen);
        }

        private static void SMix(byte[] B, int N, int r, int p)
        {
            int BLen = 128 * r * p;
            byte[] XY = new byte[256 * r]; // 2 * 128 * r
            byte[] V = new byte[128 * r * N];
            
            // For each chunk...
            for (int i = 0; i < p; i++)
            {
                // Calculate offsets
                int Bi = i * 128 * r;
                
                // Copy B[i] into X
                Buffer.BlockCopy(B, Bi, XY, 0, 128 * r);
                
                // Calculate X = ROMix(X)
                ROMix(XY, N, r, V);
                
                // Copy X back to B[i]
                Buffer.BlockCopy(XY, 0, B, Bi, 128 * r);
            }
        }

        private static void ROMix(byte[] XY, int N, int r, byte[] V)
        {
            int X = 0;  // Offset of X in XY
            int Y = 128 * r;  // Offset of Y in XY
            
            // Initialize X = B[i]
            // Already done in SMix
            
            // Fill up the lookup table V
            for (int i = 0; i < N; i++)
            {
                // V[i] = X
                Buffer.BlockCopy(XY, X, V, i * 128 * r, 128 * r);
                
                // X = BlockMix(X)
                BlockMix(XY, r, X, Y);
                
                // Swap X and Y
                int temp = X;
                X = Y;
                Y = temp;
            }
            
            // Mix it up
            for (int i = 0; i < N; i++)
            {
                // j = Integerify(X) mod N
                int j = Integerify(XY, r, X) % N;
                
                // Y = BlockMix(X XOR V[j])
                // First, XOR X with V[j]
                XorBlock(XY, X, V, j * 128 * r, 128 * r);
                
                // Then, compute Y = BlockMix(X)
                BlockMix(XY, r, X, Y);
                
                // Swap X and Y
                int temp = X;
                X = Y;
                Y = temp;
            }
            
            // If X and Y were swapped an odd number of times, swap them back
            if (X != 0)
            {
                // Swap X and Y data
                byte[] tempBlock = new byte[128 * r];
                Buffer.BlockCopy(XY, X, tempBlock, 0, 128 * r);
                Buffer.BlockCopy(XY, Y, XY, X, 128 * r);
                Buffer.BlockCopy(tempBlock, 0, XY, Y, 128 * r);
            }
        }

        private static void BlockMix(byte[] XY, int r, int X, int Y)
        {
            byte[] blockB = new byte[64];
            
            // Initialize X' = X
            Buffer.BlockCopy(XY, X + (2 * r - 1) * 64, blockB, 0, 64);
            
            // For each block...
            for (int i = 0; i < 2 * r; i++)
            {
                // Compute B = Salsa20_8(B XOR X[i])
                XorBlock(blockB, 0, XY, X + i * 64, 64);
                Salsa20_8(blockB);
                
                // Y[i] = B
                Buffer.BlockCopy(blockB, 0, XY, Y + (i / 2 + (i % 2) * r) * 64, 64);
            }
        }

        private static int Integerify(byte[] B, int r, int offset)
        {
            offset += (2 * r - 1) * 64;
            return ((int)B[offset + 0] & 0xff) |
                   (((int)B[offset + 1] & 0xff) << 8) |
                   (((int)B[offset + 2] & 0xff) << 16) |
                   (((int)B[offset + 3] & 0xff) << 24);
        }

        private static void XorBlock(byte[] dest, int destOffset, byte[] src, int srcOffset, int len)
        {
            for (int i = 0; i < len; i++)
            {
                dest[destOffset + i] ^= src[srcOffset + i];
            }
        }

        private static void Salsa20_8(byte[] B)
        {
            byte[] x = new byte[64];
            Buffer.BlockCopy(B, 0, x, 0, 64);
            
            for (int i = 0; i < 8; i += 2)
            {
                // Column round
                x[ 4] ^= RotateLeft((x[ 0] + x[12]), 7);
                x[ 8] ^= RotateLeft((x[ 4] + x[ 0]), 9);
                x[12] ^= RotateLeft((x[ 8] + x[ 4]), 13);
                x[ 0] ^= RotateLeft((x[12] + x[ 8]), 18);
                
                x[ 9] ^= RotateLeft((x[ 5] + x[ 1]), 7);
                x[13] ^= RotateLeft((x[ 9] + x[ 5]), 9);
                x[ 1] ^= RotateLeft((x[13] + x[ 9]), 13);
                x[ 5] ^= RotateLeft((x[ 1] + x[13]), 18);
                
                x[14] ^= RotateLeft((x[10] + x[ 6]), 7);
                x[ 2] ^= RotateLeft((x[14] + x[10]), 9);
                x[ 6] ^= RotateLeft((x[ 2] + x[14]), 13);
                x[10] ^= RotateLeft((x[ 6] + x[ 2]), 18);
                
                x[ 3] ^= RotateLeft((x[15] + x[11]), 7);
                x[ 7] ^= RotateLeft((x[ 3] + x[15]), 9);
                x[11] ^= RotateLeft((x[ 7] + x[ 3]), 13);
                x[15] ^= RotateLeft((x[11] + x[ 7]), 18);
                
                // Row round
                x[ 1] ^= RotateLeft((x[ 0] + x[ 3]), 7);
                x[ 2] ^= RotateLeft((x[ 1] + x[ 0]), 9);
                x[ 3] ^= RotateLeft((x[ 2] + x[ 1]), 13);
                x[ 0] ^= RotateLeft((x[ 3] + x[ 2]), 18);
                
                x[ 6] ^= RotateLeft((x[ 5] + x[ 4]), 7);
                x[ 7] ^= RotateLeft((x[ 6] + x[ 5]), 9);
                x[ 4] ^= RotateLeft((x[ 7] + x[ 6]), 13);
                x[ 5] ^= RotateLeft((x[ 4] + x[ 7]), 18);
                
                x[11] ^= RotateLeft((x[10] + x[ 9]), 7);
                x[ 8] ^= RotateLeft((x[11] + x[10]), 9);
                x[ 9] ^= RotateLeft((x[ 8] + x[11]), 13);
                x[10] ^= RotateLeft((x[ 9] + x[ 8]), 18);
                
                x[12] ^= RotateLeft((x[15] + x[14]), 7);
                x[13] ^= RotateLeft((x[12] + x[15]), 9);
                x[14] ^= RotateLeft((x[13] + x[12]), 13);
                x[15] ^= RotateLeft((x[14] + x[13]), 18);
            }
            
            for (int i = 0; i < 64; i++)
            {
                B[i] += x[i];
            }
        }

        private static byte RotateLeft(int x, int n)
        {
            return (byte)(((x << n) | (x >> (32 - n))) & 0xff);
        }

        private static byte[] PBKDF2_SHA256(byte[] password, byte[] salt, int iterationCount, int dkLen)
        {
            using (var prf = new HMACSHA256(password))
            {
                return PBKDF2(prf, salt, iterationCount, dkLen);
            }
        }

        private static byte[] PBKDF2(HMAC prf, byte[] salt, int iterationCount, int dkLen)
        {
            int hLen = prf.HashSize / 8;
            if (dkLen > (Math.Pow(2, 32) - 1) * hLen)
            {
                throw new ArgumentOutOfRangeException(nameof(dkLen), "Derived key too long");
            }
            
            int l = (dkLen + hLen - 1) / hLen;
            byte[] T = new byte[l * hLen];
            byte[] U = new byte[salt.Length + 4];
            byte[] block = new byte[hLen];
            
            Buffer.BlockCopy(salt, 0, U, 0, salt.Length);
            
            for (int i = 1; i <= l; i++)
            {
                U[salt.Length + 0] = (byte)(i >> 24);
                U[salt.Length + 1] = (byte)(i >> 16);
                U[salt.Length + 2] = (byte)(i >> 8);
                U[salt.Length + 3] = (byte)(i);
                
                byte[] F = prf.ComputeHash(U);
                Buffer.BlockCopy(F, 0, block, 0, hLen);
                
                for (int c = 1; c < iterationCount; c++)
                {
                    F = prf.ComputeHash(F);
                    for (int j = 0; j < hLen; j++)
                    {
                        block[j] ^= F[j];
                    }
                }
                
                Buffer.BlockCopy(block, 0, T, (i - 1) * hLen, hLen);
            }
            
            byte[] result = new byte[dkLen];
            Buffer.BlockCopy(T, 0, result, 0, dkLen);
            
            return result;
        }
    }
} 