using System;
using System.Security.Cryptography;

namespace UvfLib.Tests.Common.TestUtilities
{
    /// <summary>
    /// A secure random number generator for cryptographic operations
    /// </summary>
    public class SecureRandom
    {
        private readonly RandomNumberGenerator _rng;
        
        public SecureRandom()
        {
            _rng = RandomNumberGenerator.Create();
        }
        
        public void NextBytes(byte[] buffer)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));
            
            _rng.GetBytes(buffer);
        }
        
        public byte[] NextBytes(int count)
        {
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));
            
            byte[] buffer = new byte[count];
            _rng.GetBytes(buffer);
            return buffer;
        }
    }
} 