using System;

namespace CryptomatorLib.Api
{
    /// <summary>
    /// A master key that doesn't have a notion of versioning. Used for legacy vault formats where
    /// a single key is used for the entire vault, regardless of its lifetime.
    /// </summary>
    public interface PerpetualMasterkey : Masterkey
    {
        /// <summary>
        /// Creates a new instance using given raw key material.
        /// </summary>
        /// <param name="rawKey">The raw key material</param>
        /// <returns>A new PerpetualMasterkey instance</returns>
        /// <exception cref="ArgumentNullException">If rawKey is null</exception>
        /// <exception cref="ArgumentException">If rawKey is invalid</exception>
        public static PerpetualMasterkey CreateFromRaw(byte[] rawKey)
        {
            throw new NotImplementedException("Implementation classes need to override this method");
        }
        
        /// <summary>
        /// Copies this key.
        /// </summary>
        /// <returns>A new independent copy of this key</returns>
        /// <exception cref="InvalidOperationException">If this key has been destroyed</exception>
        PerpetualMasterkey Copy();
    }
} 