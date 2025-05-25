using System.Text.Json.Serialization;

namespace UvfLib.Api
{
    /// <summary>
    /// Represents an item (file or directory) within a directory listing in the vault.
    /// This structure is typically serialized as part of a dir.uvf file's content.
    /// </summary>
    public sealed class VaultChildItem
    {
        /// <summary>
        /// The type of the vault item.
        /// </summary>
        public enum ItemType
        {
            File,
            Directory
        }

        /// <summary>
        /// Gets or sets the encrypted name of the file or directory.
        /// This name typically includes the .uvf extension.
        /// </summary>
        [JsonPropertyName("name")]
        public string EncryptedName { get; set; }

        /// <summary>
        /// Gets or sets the type of the item (File or Directory).
        /// </summary>
        [JsonPropertyName("type")]
        [JsonConverter(typeof(JsonStringEnumConverter))] // Serialize enum as string
        public ItemType Type { get; set; }

        /// <summary>
        /// Gets or sets the directory ID (DirId) of the item, if it is a directory.
        /// This is typically Base64Url encoded.
        /// Null or empty if the item is a file.
        /// </summary>
        [JsonPropertyName("dirId")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] // Don't serialize if null
        public string? DirId { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="VaultChildItem"/> class.
        /// </summary>
        /// <param name="encryptedName">The encrypted name of the item.</param>
        /// <param name="type">The type of the item.</param>
        /// <param name="dirId">The directory ID, if the item is a directory. Null for files.</param>
        public VaultChildItem(string encryptedName, ItemType type, string? dirId = null)
        {
            if (string.IsNullOrEmpty(encryptedName))
            {
                throw new System.ArgumentException("Encrypted name cannot be null or empty.", nameof(encryptedName));
            }
            if (type == ItemType.Directory && string.IsNullOrEmpty(dirId))
            {
                throw new System.ArgumentException("DirId must be provided for items of type Directory.", nameof(dirId));
            }
            if (type == ItemType.File && !string.IsNullOrEmpty(dirId))
            {
                // While not strictly an error for deserialization, good for construction.
                // Consider if this should throw or just nullify dirId. For now, allow.
            }

            EncryptedName = encryptedName;
            Type = type;
            DirId = dirId;
        }
        
        // Parameterless constructor for JSON deserialization
        public VaultChildItem()
        {
            EncryptedName = string.Empty; // Or throw if not set by deserializer post-construction
        }
    }
} 