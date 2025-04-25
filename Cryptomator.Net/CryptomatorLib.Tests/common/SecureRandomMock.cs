using System;
using System.Security.Cryptography;

namespace CryptomatorLib.Tests.Common
{
    /// <summary>
    /// A mock for SecureRandom that can be used in tests.
    /// </summary>
    public class SecureRandomMock : RandomNumberGenerator
    {
        /// <summary>
        /// A "random" generator that always returns zeros
        /// </summary>
        public static readonly SecureRandomMock NULL_RANDOM = new SecureRandomMock(false);

        /// <summary>
        /// A "random" generator that always returns ones (0xFF bytes)
        /// </summary>
        public static readonly SecureRandomMock FULL_RANDOM = new SecureRandomMock(true);

        private readonly bool _fillWithOnes;

        public SecureRandomMock(bool fillWithOnes)
        {
            _fillWithOnes = fillWithOnes;
        }

        public override void GetBytes(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (_fillWithOnes)
            {
                for (int i = 0; i < data.Length; i++)
                {
                    data[i] = 0xFF;
                }
            }
            else
            {
                // Fill with zeros (already the default for a new byte array)
                Array.Clear(data, 0, data.Length);
            }
        }

        public override void GetNonZeroBytes(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (_fillWithOnes)
            {
                for (int i = 0; i < data.Length; i++)
                {
                    data[i] = 0xFF;
                }
            }
            else
            {
                // For NULL_RANDOM, still need to return non-zero bytes
                for (int i = 0; i < data.Length; i++)
                {
                    data[i] = 0x01;
                }
            }
        }
    }
}