using System.Collections.Generic;

namespace UvfLib.Api
{
    /// <summary>
    /// Represents metadata for a directory within the vault.
    /// This metadata is typically stored in an encrypted dir.uvf file.
    /// </summary>
    public interface DirectoryMetadata
    {
        /// <summary>
        /// Gets the unique ID of this directory (Base64Url encoded).
        /// </summary>
        string DirId { get; }

        /// <summary>
        /// Gets the ID of the masterkey seed revision used for cryptographic operations related to this directory.
        /// </summary>
        int SeedId { get; }

        /// <summary>
        /// Gets the list of child items (files and subdirectories) contained within this directory.
        /// This list is populated when a dir.uvf file is decrypted.
        /// </summary>
        IReadOnlyList<VaultChildItem> Children { get; } // Changed from IEnumerable to IReadOnlyList for more defined contract
    }
} 