using System;

namespace UvfLib.Tests.Common
{
    /// <summary>
    /// Interface for objects that can be destroyed.
    /// </summary>
    public interface IDestroyable
    {
        /// <summary>
        /// Destroys the object, rendering it unusable.
        /// </summary>
        void Destroy();
        
        /// <summary>
        /// Checks if the object has been destroyed.
        /// </summary>
        /// <returns>True if the object has been destroyed, false otherwise</returns>
        bool IsDestroyed();
    }
} 