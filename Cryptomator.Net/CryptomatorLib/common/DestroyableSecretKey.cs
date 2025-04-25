using System;
using System.Security.Cryptography;

namespace CryptomatorLib.Common
{
    /// <summary>
    /// A secret key that can be destroyed. Once destroyed, the key material is zeroed out and no longer available.
    /// </summary>
    public sealed class DestroyableSecretKey : IDisposable
    {
        private readonly byte[] _key;
        private readonly string _algorithm;
        private bool _destroyed;

        /// <summary>
        /// Creates a new destroyable secret key, copying the provided raw key bytes.
        /// </summary>
        /// <param name="key">The raw key material (will be copied)</param>
        /// <param name="algorithm">The algorithm name</param>
        public DestroyableSecretKey(byte[] key, string algorithm)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (string.IsNullOrEmpty(algorithm)) throw new ArgumentNullException(nameof(algorithm));

            _key = new byte[key.Length];
            Buffer.BlockCopy(key, 0, _key, 0, key.Length);
            _algorithm = algorithm;
            _destroyed = false;
        }

        /// <summary>
        /// Creates a new destroyable secret key, copying part of the provided raw key bytes.
        /// </summary>
        /// <param name="key">The raw key material (relevant part will be copied)</param>
        /// <param name="offset">The offset within the key where the key starts</param>
        /// <param name="len">The number of bytes to read from the key</param>
        /// <param name="algorithm">The algorithm name</param>
        public DestroyableSecretKey(byte[] key, int offset, int len, string algorithm)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (offset < 0) throw new ArgumentException("Invalid offset", nameof(offset));
            if (len < 0) throw new ArgumentException("Invalid length", nameof(len));
            if (key.Length < offset + len) throw new ArgumentException("Invalid offset/len");
            if (string.IsNullOrEmpty(algorithm)) throw new ArgumentNullException(nameof(algorithm));

            _key = new byte[len];
            Buffer.BlockCopy(key, offset, _key, 0, len);
            _algorithm = algorithm;
            _destroyed = false;
        }

        /// <summary>
        /// Creates a new key of given length and for use with given algorithm using entropy from the given random number generator.
        /// </summary>
        /// <param name="rng">A cryptographically secure random number source</param>
        /// <param name="algorithm">The key algorithm</param>
        /// <param name="keyLenBytes">The length of the key (in bytes)</param>
        /// <returns>A new secret key</returns>
        public static DestroyableSecretKey Generate(RandomNumberGenerator rng, string algorithm, int keyLenBytes)
        {
            if (rng == null) throw new ArgumentNullException(nameof(rng));
            if (string.IsNullOrEmpty(algorithm)) throw new ArgumentNullException(nameof(algorithm));
            if (keyLenBytes <= 0) throw new ArgumentException("Key length must be positive", nameof(keyLenBytes));

            byte[] key = new byte[keyLenBytes];
            try
            {
                rng.GetBytes(key);
                return new DestroyableSecretKey(key, algorithm);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        /// <summary>
        /// Gets the algorithm name.
        /// </summary>
        public string Algorithm
        {
            get
            {
                ThrowIfDestroyed();
                return _algorithm;
            }
        }

        /// <summary>
        /// Gets the key format.
        /// </summary>
        public string Format
        {
            get
            {
                ThrowIfDestroyed();
                return "RAW";
            }
        }

        /// <summary>
        /// Gets the raw key bytes. WARNING: This returns a direct reference to the internal key buffer.
        /// Any changes to the returned array will affect this key. Make sure to create a copy if you can't rule out mutations.
        /// </summary>
        /// <returns>The raw key material</returns>
        public byte[] GetRaw()
        {
            ThrowIfDestroyed();
            return _key;
        }

        /// <summary>
        /// Gets the raw key bytes. WARNING: This returns a direct reference to the internal key buffer.
        /// Any changes to the returned array will affect this key. Make sure to create a copy if you can't rule out mutations.
        /// </summary>
        /// <returns>The raw key material</returns>
        [Obsolete("Use GetRaw() instead")]
        public byte[] GetEncoded()
        {
            return GetRaw();
        }

        /// <summary>
        /// Gets the key bytes. Same as GetRaw() but provided for backward compatibility.
        /// </summary>
        /// <returns>The key bytes</returns>
        public byte[] GetKeyBytes()
        {
            return GetRaw();
        }

        /// <summary>
        /// Creates a new independent copy of this key.
        /// </summary>
        /// <returns>A new copy of this key</returns>
        public DestroyableSecretKey Copy()
        {
            ThrowIfDestroyed();
            return new DestroyableSecretKey(_key, _algorithm);
        }

        /// <summary>
        /// Securely destroys the key material.
        /// </summary>
        public void Destroy()
        {
            if (!_destroyed)
            {
                CryptographicOperations.ZeroMemory(_key);
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
        /// Disposes the key, calling Destroy().
        /// </summary>
        public void Dispose()
        {
            Destroy();
            GC.SuppressFinalize(this);
        }

        private void ThrowIfDestroyed()
        {
            if (_destroyed)
            {
                throw new InvalidOperationException("Key has been destroyed");
            }
        }
    }
}