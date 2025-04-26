using System;
using CryptomatorLib.Common;

namespace CryptomatorLib.Api
{
    /// <summary>
    /// A masterkey that lasts forever, i.e. does not expire.
    /// </summary>
    public class PerpetualMasterkey : Masterkey, IDisposable
    {
        /// <summary>
        /// The encryption algorithm used for the masterkey.
        /// </summary>
        public const string ENC_ALG = "AES";
        
        /// <summary>
        /// The MAC algorithm used for the masterkey.
        /// </summary>
        public const string MAC_ALG = "HmacSHA256";
        
        private byte[] _rawKey;
        private bool _destroyed;
        
        /// <summary>
        /// Creates a new perpetual masterkey with the given raw key.
        /// </summary>
        /// <param name="rawKey">The raw key material</param>
        public PerpetualMasterkey(byte[] rawKey)
        {
            _rawKey = rawKey ?? throw new ArgumentNullException(nameof(rawKey));
            _destroyed = false;
        }

        /// <summary>
        /// Gets a copy of the raw key material. Caller is responsible for zeroing out the memory when done.
        /// </summary>
        /// <returns>The raw key material</returns>
        public byte[] GetRaw()
        {
            if (_destroyed)
            {
                throw new InvalidOperationException("Masterkey has been destroyed");
            }
            
            byte[] result = new byte[_rawKey.Length];
            Buffer.BlockCopy(_rawKey, 0, result, 0, _rawKey.Length);
            return result;
        }

        /// <summary>
        /// Securely destroys the key material.
        /// </summary>
        public void Destroy()
        {
            if (!_destroyed)
            {
                Array.Clear(_rawKey, 0, _rawKey.Length);
                _destroyed = true;
            }
        }

        /// <summary>
        /// Checks if the key has been destroyed.
        /// </summary>
        /// <returns>True if the key has been destroyed, false otherwise</returns>
        public bool IsDestroyed()
        {
            return _destroyed;
        }
        
        /// <summary>
        /// Disposes the masterkey, calling Destroy().
        /// </summary>
        public void Dispose()
        {
            Destroy();
            GC.SuppressFinalize(this);
        }
    }
} 