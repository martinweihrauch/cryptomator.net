/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/

// Copyright (c) Smart In Venture GmbH 2025 of the C# Porting

using UvfLib.Api;
using UvfLib.V3;
using UvfLib.Common;

namespace UvfLib.VaultHelpers
{
    /// <summary>
    /// Provides helper methods for file operations within a vault, including size calculations
    /// and other file-related utilities.
    /// </summary>
    internal static class VaultFileHelper
    {
        // Constants for file structure sizes
        private const int MAGIC_BYTES_SIZE = 4;
        private const int SEED_ID_SIZE = 4;
        private const int NONCE_SIZE = 12;
        private const int CONTENT_KEY_SIZE = 32;
        private const int TAG_SIZE = 16;
        private const int HEADER_SIZE = MAGIC_BYTES_SIZE + SEED_ID_SIZE + NONCE_SIZE + CONTENT_KEY_SIZE + TAG_SIZE; // 68 bytes
        private const int CHUNK_SIZE = 32768; // 32KB chunks
        private const int CHUNK_OVERHEAD = Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE; // 28 bytes per chunk

        /// <summary>
        /// Calculates the expected size of an encrypted file based on its original size.
        /// </summary>
        /// <param name="sourceFileSize">The size of the source file in bytes</param>
        /// <returns>The expected size of the encrypted file in bytes</returns>
        public static long CalculateExpectedEncryptedSize(long sourceFileSize)
        {
            // Calculate how many complete chunks we'll need
            long completeChunks = sourceFileSize / CHUNK_SIZE;
            
            // Calculate if we need an additional chunk for remaining bytes
            long remainingBytes = sourceFileSize % CHUNK_SIZE;
            long totalChunks = remainingBytes > 0 ? completeChunks + 1 : completeChunks;
            
            // Calculate total overhead from chunks
            long totalChunkOverhead = totalChunks * CHUNK_OVERHEAD;
            
            // Total size = header + source file size + total chunk overhead
            return HEADER_SIZE + sourceFileSize + totalChunkOverhead;
        }

        /// <summary>
        /// Calculates the expected size of a decrypted file based on its encrypted size.
        /// </summary>
        /// <param name="encryptedFileSize">The size of the encrypted file in bytes</param>
        /// <returns>The expected size of the decrypted file in bytes</returns>
        /// <exception cref="ArgumentException">Thrown when the encrypted file size is invalid</exception>
        public static long CalculateExpectedDecryptedSize(long encryptedFileSize)
        {
            // First remove the header size
            long sizeWithoutHeader = encryptedFileSize - HEADER_SIZE;
            if (sizeWithoutHeader <= 0)
            {
                throw new ArgumentException("Encrypted file size is too small to be valid", nameof(encryptedFileSize));
            }

            // Calculate total chunk overhead
            long totalOverhead = 0;
            long remainingBytes = sizeWithoutHeader;
            
            while (remainingBytes > 0)
            {
                totalOverhead += CHUNK_OVERHEAD;
                remainingBytes -= (CHUNK_SIZE + CHUNK_OVERHEAD);
            }

            // Expected decrypted size = encrypted size - header - total chunk overhead
            long expectedSize = encryptedFileSize - HEADER_SIZE - totalOverhead;
            
            if (expectedSize < 0)
            {
                throw new ArgumentException("Invalid encrypted file size or corrupted file", nameof(encryptedFileSize));
            }

            return expectedSize;
        }
    }
} 