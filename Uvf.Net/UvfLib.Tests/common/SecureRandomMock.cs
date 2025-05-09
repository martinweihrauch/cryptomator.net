using System;
using System.Security.Cryptography;

namespace UvfLib.Tests.Common
{
    /// <summary>
    /// A mock for RandomNumberGenerator that always returns zeros.
    /// </summary>
    public class SecureRandomMock : RandomNumberGenerator
    {
        /// <summary>
        /// A RandomNumberGenerator that always generates zeros.
        /// </summary>
        public static readonly RandomNumberGenerator NULL_RANDOM = new SecureRandomMock();
        
        private SecureRandomMock()
        {
        }
        
        /// <summary>
        /// Fills the provided buffer with zeros.
        /// </summary>
        /// <param name="data">The buffer to fill</param>
        public override void GetBytes(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            
            Array.Clear(data, 0, data.Length);
        }
        
        /// <summary>
        /// Fills the provided span with zeros.
        /// </summary>
        /// <param name="data">The span to fill</param>
        public override void GetBytes(Span<byte> data)
        {
            data.Clear();
        }
    }
}