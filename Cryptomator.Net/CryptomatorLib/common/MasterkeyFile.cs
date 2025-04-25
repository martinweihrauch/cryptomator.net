using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptomatorLib.Common
{
    /// <summary>
    /// Represents a masterkey file with its metadata.
    /// </summary>
    public class MasterkeyFile
    {
        private const int CURRENT_VERSION = 3;
        
        /// <summary>
        /// The optional UTF-8 encoded JSON representation of the keyfile.
        /// </summary>
        private byte[]? _rawJsonRepresentation;

        /// <summary>
        /// Gets or sets the version of this masterkey file.
        /// </summary>
        [JsonPropertyName("version")]
        public int Version { get; set; } = CURRENT_VERSION;
        
        /// <summary>
        /// Gets or sets the scrypt cost parameter.
        /// </summary>
        [JsonPropertyName("scryptCostParam")]
        public int ScryptCostParam { get; set; }
        
        /// <summary>
        /// Gets or sets the scrypt block size.
        /// </summary>
        [JsonPropertyName("scryptBlockSize")]
        public int ScryptBlockSize { get; set; }
        
        /// <summary>
        /// Gets or sets the scrypt parallelism parameter.
        /// </summary>
        [JsonPropertyName("scryptParallelism")]
        public int ScryptParallelism { get; set; }
        
        /// <summary>
        /// Gets or sets the primary masterkey.
        /// </summary>
        [JsonPropertyName("primaryMasterKey")]
        public string? PrimaryMasterkey { get; set; }
        
        /// <summary>
        /// Gets or sets the primary masterkey's nonce (IV).
        /// </summary>
        [JsonPropertyName("primaryMasterKeyNonce")]
        public string? PrimaryMasterkeyNonce { get; set; }
        
        /// <summary>
        /// Gets or sets the MAC of the primary masterkey.
        /// </summary>
        [JsonPropertyName("primaryMasterKeyMac")]
        public string? PrimaryMasterkeyMac { get; set; }
        
        /// <summary>
        /// Gets or sets the version of the vault.
        /// </summary>
        [JsonPropertyName("vaultVersion")]
        public int VaultVersion { get; set; }
        
        /// <summary>
        /// Gets or sets the encryption scheme used for content encryption.
        /// </summary>
        [JsonPropertyName("contentEncryptionScheme")]
        public string? ContentEncryptionScheme { get; set; }
        
        /// <summary>
        /// Gets or sets the encryption scheme used for filename encryption.
        /// </summary>
        [JsonPropertyName("filenameEncryptionScheme")]
        public string? FilenameEncryptionScheme { get; set; }
        
        /// <summary>
        /// Gets or sets the key ID for UVF masterkeys.
        /// </summary>
        [JsonPropertyName("keyID")]
        public string? KeyId { get; set; }
        
        /// <summary>
        /// Gets or sets the salt for UVF masterkeys.
        /// </summary>
        [JsonPropertyName("salt")]
        public string? Salt { get; set; }
        
        /// <summary>
        /// Gets or sets the iterations for UVF masterkeys.
        /// </summary>
        [JsonPropertyName("iterations")]
        public int Iterations { get; set; }
        
        /// <summary>
        /// Gets or sets the wrapping algorithm for UVF masterkeys.
        /// </summary>
        [JsonPropertyName("wrappingAlgorithm")]
        public string? WrappingAlgorithm { get; set; }
        
        /// <summary>
        /// Gets or sets the KDF algorithm for UVF masterkeys.
        /// </summary>
        [JsonPropertyName("kdfAlgorithm")]
        public string? KdfAlgorithm { get; set; }
        
        /// <summary>
        /// Gets or sets the wrapped key for UVF masterkeys.
        /// </summary>
        [JsonPropertyName("wrappedKey")]
        public string? WrappedKey { get; set; }
        
        /// <summary>
        /// Gets or sets the encryption scheme for UVF. 
        /// </summary>
        [JsonPropertyName("encryptionAlgorithm")]
        public string? EncryptionAlgorithm { get; set; }
        
        /// <summary>
        /// Creates a masterkey file from its JSON representation.
        /// </summary>
        /// <param name="json">The JSON representation</param>
        /// <returns>The parsed masterkey file</returns>
        public static MasterkeyFile FromJson(byte[] json)
        {
            if (json == null)
            {
                throw new ArgumentNullException(nameof(json));
            }
            
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };
            
            var masterkeyFile = JsonSerializer.Deserialize<MasterkeyFile>(json, options) 
                                ?? throw new JsonException("Failed to parse masterkey file");
            masterkeyFile._rawJsonRepresentation = json;
            return masterkeyFile;
        }

        /// <summary>
        /// Creates a masterkey file from its JSON representation.
        /// </summary>
        /// <param name="json">The JSON representation</param>
        /// <returns>The parsed masterkey file</returns>
        public static MasterkeyFile FromJson(string json)
        {
            if (json == null)
            {
                throw new ArgumentNullException(nameof(json));
            }
            
            return FromJson(Encoding.UTF8.GetBytes(json));
        }

        /// <summary>
        /// Converts this masterkey file to its JSON representation.
        /// </summary>
        /// <returns>The JSON representation</returns>
        public byte[] ToJson()
        {
            if (_rawJsonRepresentation != null)
            {
                return _rawJsonRepresentation;
            }
            
            var options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                WriteIndented = true
            };
            
            return _rawJsonRepresentation = JsonSerializer.SerializeToUtf8Bytes(this, options);
        }

        /// <summary>
        /// Converts this masterkey file to its JSON representation as a string.
        /// </summary>
        /// <returns>The JSON representation</returns>
        public string ToJsonString()
        {
            return Encoding.UTF8.GetString(ToJson());
        }
    }
} 