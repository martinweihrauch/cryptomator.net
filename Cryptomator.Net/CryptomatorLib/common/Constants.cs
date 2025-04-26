using System;

namespace CryptomatorLib.Common
{
    /// <summary>
    /// Constants used throughout the library.
    /// </summary>
    public static class Constants
    {
        // GCM-specific constants
        public const int GCM_NONCE_SIZE = 12; // 12 bytes (96 bits) for AES-GCM nonce
        public const int GCM_TAG_SIZE = 16;   // 16 bytes (128 bits) for GCM authentication tag

        // V3 format constants
        public const int PAYLOAD_SIZE = 32 * 1024; // 32KB payload size
        public const int CHUNK_SIZE = GCM_NONCE_SIZE + PAYLOAD_SIZE + GCM_TAG_SIZE; // Full chunk size

        // ... existing code ...
    }
} 