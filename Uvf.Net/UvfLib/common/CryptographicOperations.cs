using System;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;

namespace UvfLib.Common
{
    /// <summary>
    /// Provides cryptographic operations for secure memory handling.
    /// </summary>
    public static class CryptographicOperations
    {
        /// <summary>
        /// Overwrite the memory pointed to by the reference with zeros.
        /// </summary>
        /// <param name="data">The reference to the memory to zero.</param>
        public static void ZeroMemory(byte[] data)
        {
            if (data == null)
                return;

            // Use .NET Core's built-in method if available
            if (RuntimeFeature.IsDynamicCodeSupported)
            {
                try
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(data);
                    return;
                }
                catch
                {
                    // Fall back to manual implementation
                }
            }

            // Manual implementation as fallback
            Array.Clear(data, 0, data.Length);
        }

        /// <summary>
        /// Determines if two sequences of bytes are equal.
        /// </summary>
        /// <param name="left">The first span to compare.</param>
        /// <param name="right">The second span to compare.</param>
        /// <returns>
        /// True if the sequences are equal; otherwise, false.
        /// </returns>
        public static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left == null || right == null)
                return left == right;

            if (left.Length != right.Length)
                return false;

            // Use .NET Core's built-in method if available
            if (RuntimeFeature.IsDynamicCodeSupported)
            {
                try
                {
                    return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                        left.AsSpan(), right.AsSpan());
                }
                catch
                {
                    // Fall back to manual implementation
                }
            }

            // Manual implementation as fallback
            int result = 0;
            for (int i = 0; i < left.Length; i++)
            {
                result |= left[i] ^ right[i];
            }

            return result == 0;
        }
    }
}