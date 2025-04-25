using System;

namespace CryptomatorLib.Api
{
    /// <summary>
    /// A secret key that can be destroyed. Once destroyed, the key material is zeroed out and no longer available.
    /// </summary>
    public interface Masterkey : IDisposable
    {
        /// <summary>
        /// Gets a copy of the raw key material. Caller is responsible for zeroing out the memory when done.
        /// </summary>
        /// <returns>The raw key material</returns>
        byte[] GetRaw();

        /// <summary>
        /// Securely destroys the key material.
        /// </summary>
        void Destroy();

        /// <summary>
        /// Checks if the key has been destroyed.
        /// </summary>
        /// <returns>True if the key has been destroyed, false otherwise</returns>
        bool IsDestroyed();
    }
} 