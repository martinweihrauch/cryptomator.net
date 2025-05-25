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
        /// This name typically includes the .uvf extension for files, but not necessarily for directories listed in parent dir.uvf.
        /// </summary>
        [JsonPropertyName("name")]
        public string EncryptedName { get; set; }

        /// <summary>
        /// Gets or sets the type of the item (File or Directory).
        /// </summary>
        [JsonPropertyName("type")]
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public ItemType Type { get; set; }

        /// <summary>
        /// Gets or sets the Base64Url encoded Directory ID of the item, if it is a directory.
        /// This is null for files.
        /// </summary>
        [JsonPropertyName("dirId")]
        public string? DirId { get; set; }
    }
} 