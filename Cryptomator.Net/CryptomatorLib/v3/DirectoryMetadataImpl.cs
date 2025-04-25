using CryptomatorLib.Api;
using System;

namespace CryptomatorLib.V3
{
    /// <summary>
    /// Implementation of the DirectoryMetadata interface for v3 format.
    /// </summary>
    internal sealed class DirectoryMetadataImpl : DirectoryMetadata
    {
        private readonly int _seedId;
        private readonly byte[] _dirId;

        /// <summary>
        /// Creates a new directory metadata.
        /// </summary>
        /// <param name="seedId">The ID of the seed to derive subkeys</param>
        /// <param name="dirId">The directory ID</param>
        public DirectoryMetadataImpl(int seedId, byte[] dirId)
        {
            _seedId = seedId;
            _dirId = dirId ?? throw new ArgumentNullException(nameof(dirId));
        }

        /// <summary>
        /// Casts the given metadata to DirectoryMetadataImpl.
        /// </summary>
        /// <param name="metadata">The metadata to cast</param>
        /// <returns>The metadata as DirectoryMetadataImpl</returns>
        /// <exception cref="ArgumentException">If the metadata is not a DirectoryMetadataImpl</exception>
        internal static DirectoryMetadataImpl Cast(DirectoryMetadata metadata)
        {
            if (metadata is DirectoryMetadataImpl metadataImpl)
            {
                return metadataImpl;
            }
            else
            {
                throw new ArgumentException($"Unsupported metadata type {metadata.GetType()}", nameof(metadata));
            }
        }

        /// <summary>
        /// Gets the directory ID.
        /// </summary>
        /// <returns>The directory ID</returns>
        public byte[] DirId()
        {
            return _dirId;
        }

        /// <summary>
        /// Gets the seed ID.
        /// </summary>
        /// <returns>The seed ID</returns>
        public int SeedId()
        {
            return _seedId;
        }
    }
}