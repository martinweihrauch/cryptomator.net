using System;
using System.Collections.Generic;

namespace CryptomatorLib.Tests.Common
{
    /// <summary>
    /// Utility methods for handling destroyable objects.
    /// </summary>
    public static class Destroyables
    {
        /// <summary>
        /// Destroys an object silently, ignoring any exceptions that occur.
        /// </summary>
        /// <param name="destroyable">The object to destroy</param>
        public static void DestroySilently(IDestroyable? destroyable)
        {
            if (destroyable == null) 
            {
                return;
            }
            
            try
            {
                destroyable.Destroy();
            }
            catch (Exception)
            {
                // Ignore exceptions during destruction
            }
        }
        
        /// <summary>
        /// Destroys multiple objects silently, ignoring any exceptions that occur.
        /// </summary>
        /// <param name="destroyables">The objects to destroy</param>
        public static void DestroySilently(params IDestroyable?[] destroyables)
        {
            if (destroyables == null)
            {
                return;
            }
            
            foreach (var destroyable in destroyables)
            {
                DestroySilently(destroyable);
            }
        }
        
        /// <summary>
        /// Destroys multiple objects silently, ignoring any exceptions that occur.
        /// </summary>
        /// <param name="destroyables">The objects to destroy</param>
        public static void DestroySilently(IEnumerable<IDestroyable?> destroyables)
        {
            if (destroyables == null)
            {
                return;
            }
            
            foreach (var destroyable in destroyables)
            {
                DestroySilently(destroyable);
            }
        }
    }
} 