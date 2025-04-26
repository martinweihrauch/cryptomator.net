using System;
using System.Security.Cryptography;

namespace CryptomatorLib.Tests.Common.TestUtilities
{
    /// <summary>
    /// A mock implementation of SecureRandom for testing
    /// This is meant to simulate the behavior from Java's SecureRandom
    /// </summary>
    public class SecureRandom
    {
        private readonly RandomNumberGenerator _rng;
        private readonly byte[] _seed;
        
        public SecureRandom()
        {
            _rng = RandomNumberGenerator.Create();
            _seed = new byte[32];
            _rng.GetBytes(_seed);
        }
        
        public SecureRandom(byte[] seed)
        {
            _rng = RandomNumberGenerator.Create();
            _seed = seed ?? throw new ArgumentNullException(nameof(seed));
        }
        
        public void SetSeed(byte[] seed)
        {
            if (seed == null)
                throw new ArgumentNullException(nameof(seed));
                
            Buffer.BlockCopy(seed, 0, _seed, 0, Math.Min(seed.Length, _seed.Length));
        }
        
        public void NextBytes(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
                
            _rng.GetBytes(bytes);
        }
        
        public byte[] GenerateSeed(int numBytes)
        {
            byte[] seed = new byte[numBytes];
            _rng.GetBytes(seed);
            return seed;
        }
        
        public void Dispose()
        {
            _rng.Dispose();
        }
    }
} 