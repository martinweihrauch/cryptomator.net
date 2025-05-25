using UvfLib.Api;
using System;
using System.Collections.Generic;
using System.Linq;
using UvfLib.Common; // For Base64Url if used here, or for general utilities

namespace UvfLib.V3
{
    /// <summary>
    /// Implementation of the DirectoryMetadata interface for v3 format.
    /// This typically represents the deserialized and decrypted content of a dir.uvf file.
    /// </summary>
    internal sealed class DirectoryMetadataImpl : DirectoryMetadata
    {
        private readonly int _seedId;
        private readonly byte[] _dirIdBytes; // Store as raw bytes internally
        private readonly List<VaultChildItem> _children;

        // Public getters for the interface
        public string DirId => Base64Url.Encode(_dirIdBytes); // Encode on demand for the interface
        public int SeedId => _seedId;
        public IReadOnlyList<VaultChildItem> Children => _children.AsReadOnly();

        /// <summary>
        /// Creates a new directory metadata.
        /// </summary>
        /// <param name="seedId">The masterkey seed ID.</param>
        /// <param name="dirIdBytes">The raw bytes of the directory ID.</param>
        /// <param name="children">The list of child items. Can be null or empty for new directories.</param>
        /// <exception cref="ArgumentNullException">If dirIdBytes is null.</exception>
        /// <exception cref="ArgumentException">If dirIdBytes length is invalid.</exception>
        public DirectoryMetadataImpl(int seedId, byte[] dirIdBytes, List<VaultChildItem>? children)
        {
            if (dirIdBytes == null) throw new ArgumentNullException(nameof(dirIdBytes));
            if (dirIdBytes.Length != Constants.DIR_ID_SIZE) throw new ArgumentException($"DirId must be {Constants.DIR_ID_SIZE} bytes long.", nameof(dirIdBytes));

            _seedId = seedId;
            _dirIdBytes = (byte[])dirIdBytes.Clone(); // Defensive copy
            _children = children ?? new List<VaultChildItem>();
        }

        /// <summary>
        /// Gets the raw bytes of the directory ID.
        /// </summary>
        /// <returns>A clone of the internal DirId byte array.</returns>
        internal byte[] GetDirIdBytes()
        {
            return (byte[])_dirIdBytes.Clone(); // Return a clone for safety
        }

        /// <summary>
        /// Adds a child item to this directory's metadata.
        /// </summary>
        /// <param name="child">The child item to add.</param>
        internal void AddChild(VaultChildItem child)
        {
            if (child == null) throw new ArgumentNullException(nameof(child));
            _children.Add(child);
        }

        /// <summary>
        /// Clears all child items from this directory's metadata.
        /// </summary>
        internal void ClearChildren()
        {
            _children.Clear();
        }

        /// <summary>
        /// Helper to cast DirectoryMetadata to DirectoryMetadataImpl.
        /// </summary>
        public static DirectoryMetadataImpl Cast(DirectoryMetadata metadata)
        {
            if (metadata is DirectoryMetadataImpl impl)
            {
                return impl;
            }
            throw new ArgumentException("Metadata object is not an instance of DirectoryMetadataImpl.", nameof(metadata));
        }
    }
}