using System;
using System.Collections.Generic;
// Ensure VaultChildItem is accessible; UvfLib.Api.VaultChildItem if needed, or just 'using UvfLib.Api;'

namespace UvfLib.Api
{
    /// <summary>
    /// Represents directory metadata, including its unique ID, associated masterkey seed, and children.
    /// </summary>
    public interface DirectoryMetadata
    {
        /// <summary>
        /// Gets the Base64Url encoded Directory ID.
        /// This ID is unique for each directory in the vault.
        /// </summary>
        string DirId { get; }

        /// <summary>
        /// Gets the masterkey seed ID (often referred to as revision) 
        /// used for cryptographic operations related to this directory and its direct children's names.
        /// </summary>
        int SeedId { get; }

        /// <summary>
        /// Gets a read-only list of child items (files and directories) 
        /// contained within this directory. This list is typically populated 
        /// when directory metadata (e.g., from a dir.uvf file) is decrypted.
        /// </summary>
        IReadOnlyList<VaultChildItem> Children { get; }
    }
} 