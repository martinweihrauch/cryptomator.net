using System;
using UvfLib.Common;
using System.Security.Cryptography;

namespace UvfLib.Api
{
    /// <summary>
    /// A concrete, non-revolving master key implementation.
    /// (Original structure before refactoring attempt)
    /// </summary>
    public class PerpetualMasterkey : Masterkey // Should implement original Api.Masterkey
    {
        /// <summary>
        /// The encryption algorithm used for the masterkey.
        /// </summary>
        public const string ENC_ALG = "AES";

        /// <summary>
        /// The MAC algorithm used for the masterkey.
        /// </summary>
        public const string MAC_ALG = "HmacSHA256";

        public const int SubkeyLengthBytes = 32;
        private readonly byte[] _key;
        private bool _destroyed;

        /// <summary>
        /// Creates a new perpetual masterkey with the given raw key.
        /// </summary>
        /// <param name="key">The raw key material</param>
        public PerpetualMasterkey(byte[] key)
        {
            if (key.Length != SubkeyLengthBytes * 2)
                throw new ArgumentException($"Invalid raw key length {key.Length}", nameof(key));

            _key = new byte[key.Length];
            Buffer.BlockCopy(key, 0, _key, 0, key.Length);
            _destroyed = false;
        }

        public DestroyableSecretKey GetEncKey()
        {
            if (_destroyed) throw new InvalidOperationException("Key destroyed");
            return new DestroyableSecretKey(_key, 0, SubkeyLengthBytes, "AES");
        }

        public DestroyableSecretKey GetMacKey()
        {
            if (_destroyed) throw new InvalidOperationException("Key destroyed");
            return new DestroyableSecretKey(_key, SubkeyLengthBytes, SubkeyLengthBytes, "HmacSHA256");
        }

        public byte[] GetEncoded()
        {
            if (_destroyed) throw new InvalidOperationException("Key destroyed");
            byte[] copy = new byte[_key.Length];
            Buffer.BlockCopy(_key, 0, copy, 0, _key.Length);
            return copy;
        }

        /// <summary>
        /// Gets a copy of the raw key material. Caller is responsible for zeroing out the memory when done.
        /// </summary>
        /// <returns>The raw key material</returns>
        public byte[] GetRaw()
        {
            if (_destroyed) throw new InvalidOperationException("Masterkey has been destroyed");
            byte[] result = new byte[_key.Length];
            Buffer.BlockCopy(_key, 0, result, 0, _key.Length);
            return result;
        }

        /// <summary>
        /// Securely destroys the key material.
        /// </summary>
        public void Destroy()
        {
            if (!_destroyed)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(_key);
                _destroyed = true;
            }
        }

        /// <summary>
        /// Checks if the key has been destroyed.
        /// </summary>
        /// <returns>True if the key has been destroyed, false otherwise</returns>
        public bool IsDestroyed() // Method, not property
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

        /// <summary>
        /// Root directory ID for the masterkey.
        /// </summary>
        /// <returns>The root directory ID</returns>
        public byte[] RootDirId()
        {
            // Consistent with Java PerpetualMasterkey and Uvf spec
            return Array.Empty<byte>();
        }

        /// <summary>
        /// Overrides the default equality comparison.
        /// </summary>
        /// <param name="obj">The object to compare with the current object.</param>
        /// <returns>True if the specified object is equal to the current object; otherwise, false.</returns>
        public override bool Equals(object? obj)
        {
            if (obj is PerpetualMasterkey other)
            {
                if (this._destroyed || other._destroyed)
                    return this._destroyed && other._destroyed; // Equal only if both destroyed
                // Use FixedTimeEquals for constant-time comparison if keys are not destroyed
                return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(this._key, other._key);
            }
            return false;
        }

        /// <summary>
        /// Overrides the default hash code.
        /// </summary>
        /// <returns>A hash code for the current object.</returns>
        public override int GetHashCode()
        {
            // Hash code based on key material (consistent with Equals)
            // Avoid hashing destroyed keys for security
            return _destroyed ? 0 : System.Collections.StructuralComparisons.StructuralEqualityComparer.GetHashCode(_key);
        }
    }
}