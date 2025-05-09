using System;
using System.Security.Cryptography;

namespace UvfLib.Tests.Common.TestUtilities
{
    /// <summary>
    /// A mock version of SecureRandom for testing
    /// </summary>
    public class SecureRandomMock
    {
        /// <summary>
        /// A "null" random that doesn't actually randomize - it returns zeros for testing
        /// </summary>
        public static readonly RandomNumberGenerator NULL_RANDOM = new NullRandomNumberGenerator();
        
        private class NullRandomNumberGenerator : RandomNumberGenerator
        {
            public override void GetBytes(byte[] data)
            {
                // For testing, just fill with zeros
                Array.Clear(data, 0, data.Length);
            }
            
            public override void GetNonZeroBytes(byte[] data)
            {
                // For testing, fill with ones
                for (int i = 0; i < data.Length; i++)
                {
                    data[i] = 1;
                }
            }
        }
    }
} 