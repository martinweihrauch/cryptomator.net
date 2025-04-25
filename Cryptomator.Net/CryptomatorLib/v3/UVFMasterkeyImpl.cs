using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Text.Json;
using CryptomatorLib.Api;
using CryptomatorLib.Common;

namespace CryptomatorLib.V3
{
    /// <summary>
    /// Implementation of the UVFMasterkey interface for Universal Vault Format.
    /// </summary>
    internal sealed class UVFMasterkeyImpl : UVFMasterkey, DestroyableMasterkey
    {
        private static readonly byte[] ROOT_DIRID_KDF_CONTEXT = Encoding.ASCII.GetBytes("rootDirId");

        private readonly Dictionary<int, byte[]> _seeds;
        private readonly byte[] _kdfSalt;
        private readonly int _initialSeed;
        private readonly int _latestSeed;
        private bool _destroyed;

        // Properties to implement UVFMasterkey interface
        public Dictionary<int, byte[]> Seeds => _seeds;
        public byte[] KdfSalt => _kdfSalt;
        public int InitialSeed => _initialSeed;
        public int LatestSeed => _latestSeed;
        public byte[] RootDirId => GetRootDirId();
        public int FirstRevision => GetFirstRevision();

        /// <summary>
        /// Creates a new UVF masterkey.
        /// </summary>
        /// <param name="seeds">The seeds</param>
        /// <param name="kdfSalt">The KDF salt</param>
        /// <param name="initialSeed">The initial seed ID</param>
        /// <param name="latestSeed">The latest seed ID</param>
        public UVFMasterkeyImpl(Dictionary<int, byte[]> seeds, byte[] kdfSalt, int initialSeed, int latestSeed)
        {
            if (seeds == null)
                throw new ArgumentNullException(nameof(seeds));
            if (kdfSalt == null)
                throw new ArgumentNullException(nameof(kdfSalt));

            _seeds = new Dictionary<int, byte[]>(seeds.Count);
            foreach (var entry in seeds)
            {
                byte[] seedCopy = new byte[entry.Value.Length];
                Buffer.BlockCopy(entry.Value, 0, seedCopy, 0, entry.Value.Length);
                _seeds.Add(entry.Key, seedCopy);
            }

            _kdfSalt = new byte[kdfSalt.Length];
            Buffer.BlockCopy(kdfSalt, 0, _kdfSalt, 0, kdfSalt.Length);

            _initialSeed = initialSeed;
            _latestSeed = latestSeed;
            _destroyed = false;
        }

        /// <summary>
        /// Creates a UVF masterkey from a JSON payload.
        /// </summary>
        /// <param name="json">The JSON payload</param>
        /// <returns>A UVF masterkey</returns>
        public static UVFMasterkey FromDecryptedPayload(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentException("JSON payload must not be null or empty", nameof(json));

            using JsonDocument doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;

            // Validate file format
            if (!root.TryGetProperty("fileFormat", out JsonElement fileFormatElem) ||
                fileFormatElem.GetString() != "AES-256-GCM-32k")
            {
                throw new ArgumentException("Invalid fileFormat value");
            }

            // Validate name format
            if (!root.TryGetProperty("nameFormat", out JsonElement nameFormatElem) ||
                nameFormatElem.GetString() != "AES-SIV-512-B64URL")
            {
                throw new ArgumentException("Invalid nameFormat value");
            }

            // Validate KDF
            if (!root.TryGetProperty("kdf", out JsonElement kdfElem) ||
                kdfElem.GetString() != "HKDF-SHA512")
            {
                throw new ArgumentException("Invalid kdf value");
            }

            // Validate seeds are present
            if (!root.TryGetProperty("seeds", out JsonElement seedsElem) ||
                seedsElem.ValueKind != JsonValueKind.Object)
            {
                throw new ArgumentException("Missing or invalid seeds");
            }

            // Extract base64 values
            byte[] initialSeed = Convert.FromBase64String(root.GetProperty("initialSeed").GetString());
            byte[] latestSeed = Convert.FromBase64String(root.GetProperty("latestSeed").GetString());
            byte[] kdfSalt = Convert.FromBase64String(root.GetProperty("kdfSalt").GetString());

            // Parse seeds
            Dictionary<int, byte[]> seeds = new Dictionary<int, byte[]>();
            foreach (JsonProperty seedProp in seedsElem.EnumerateObject())
            {
                byte[] seedIdBytes = Convert.FromBase64String(seedProp.Name);
                int seedId = BinaryPrimitives.ReadInt32BigEndian(seedIdBytes);
                byte[] seedValue = Convert.FromBase64String(seedProp.Value.GetString());
                seeds.Add(seedId, seedValue);
            }

            int initialSeedId = BinaryPrimitives.ReadInt32BigEndian(initialSeed);
            int latestSeedId = BinaryPrimitives.ReadInt32BigEndian(latestSeed);

            return new UVFMasterkeyImpl(seeds, kdfSalt, initialSeedId, latestSeedId);
        }

        /// <summary>
        /// Creates a UVF masterkey from raw key material.
        /// </summary>
        /// <param name="rawKey">The raw key material</param>
        /// <returns>A UVF masterkey</returns>
        /// <exception cref="ArgumentNullException">If rawKey is null</exception>
        /// <exception cref="ArgumentException">If rawKey is invalid</exception>
        public static UVFMasterkey CreateFromRaw(byte[] rawKey)
        {
            if (rawKey == null)
                throw new ArgumentNullException(nameof(rawKey));

            try
            {
                // Convert raw key to JSON string
                string json = Encoding.UTF8.GetString(rawKey);

                // Parse the JSON to create a UVFMasterkey
                return FromDecryptedPayload(json);
            }
            catch (Exception ex) when (ex is JsonException || ex is ArgumentException || ex is FormatException)
            {
                throw new ArgumentException("Invalid raw key format", nameof(rawKey), ex);
            }
        }

        /// <summary>
        /// Gets the version of this master key.
        /// </summary>
        /// <returns>The version</returns>
        public int Version()
        {
            ThrowIfDestroyed();
            return 1; // Current UVF version is 1
        }

        /// <summary>
        /// Gets the current revision of this key.
        /// </summary>
        /// <returns>The current revision</returns>
        public int GetCurrentRevision()
        {
            ThrowIfDestroyed();
            return _latestSeed;
        }

        /// <summary>
        /// Creates a new independent copy of this master key.
        /// </summary>
        /// <returns>A new copy of this master key</returns>
        [return: MaybeNull]
        public UVFMasterkey Copy()
        {
            ThrowIfDestroyed();
            return new UVFMasterkeyImpl(_seeds, _kdfSalt, _initialSeed, _latestSeed);
        }

        /// <summary>
        /// Gets key data based on the master key, that can be used to derive secrets.
        /// </summary>
        /// <param name="context">The context for the derivation (will be UTF-8 encoded)</param>
        /// <returns>The derived key data</returns>
        public byte[] KeyData(string context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            return KeyData(Encoding.UTF8.GetBytes(context));
        }

        /// <summary>
        /// Gets key data based on the master key, that can be used to derive secrets.
        /// </summary>
        /// <param name="context">The context for the derivation</param>
        /// <returns>The derived key data</returns>
        public byte[] KeyData(byte[] context)
        {
            ThrowIfDestroyed();
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            return HKDFHelper.HkdfSha512(_kdfSalt, _seeds[_latestSeed], context, 32);
        }

        /// <summary>
        /// Gets a deterministically generated unique key identifier for this key.
        /// </summary>
        /// <returns>A key identifier that is unique to this key</returns>
        public byte[] KeyID()
        {
            ThrowIfDestroyed();
            // Use the root directory ID as the key ID
            return HKDFHelper.HkdfSha512(_kdfSalt, _seeds[_initialSeed], ROOT_DIRID_KDF_CONTEXT, 32);
        }

        /// <summary>
        /// The key ID as a hexadecimal string.
        /// </summary>
        /// <returns>The key ID as a hexadecimal string</returns>
        public string KeyIDHex()
        {
            byte[] keyId = KeyID();
            return BitConverter.ToString(keyId).Replace("-", "").ToLowerInvariant();
        }

        /// <summary>
        /// Derive a key from this master key.
        /// </summary>
        /// <param name="seedId">Seed identifier</param>
        /// <param name="size">Key size in bytes</param>
        /// <param name="context">Context for key derivation</param>
        /// <param name="algorithm">Algorithm for which this key will be used</param>
        /// <returns>A derived key that must be destroyed after usage</returns>
        public DestroyableSecretKey SubKey(int seedId, int size, byte[] context, string algorithm)
        {
            ThrowIfDestroyed();

            if (context == null)
                throw new ArgumentNullException(nameof(context));
            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentException("Algorithm must not be null or empty", nameof(algorithm));

            if (!_seeds.ContainsKey(seedId))
                throw new ArgumentException($"No seed for revision {seedId}", nameof(seedId));

            byte[] subkey = HKDFHelper.HkdfSha512(_kdfSalt, _seeds[seedId], context, size);

            try
            {
                return new DestroyableSecretKey(subkey, algorithm);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(subkey);
            }
        }

        /// <summary>
        /// Gets a copy of the raw key material. Caller is responsible for zeroing out the memory when done.
        /// </summary>
        /// <returns>The raw key material</returns>
        public byte[] GetRaw()
        {
            ThrowIfDestroyed();

            // Create a JSON representation of the master key
            var jsonObject = new Dictionary<string, object>();

            // Add standard fields
            jsonObject["fileFormat"] = "AES-256-GCM-32k";
            jsonObject["nameFormat"] = "AES-SIV-512-B64URL";
            jsonObject["kdf"] = "HKDF-SHA512";

            // Convert seed IDs and values to base64
            var seedsObject = new Dictionary<string, string>();
            foreach (var entry in _seeds)
            {
                byte[] seedIdBytes = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(seedIdBytes, entry.Key);
                string seedIdBase64 = Convert.ToBase64String(seedIdBytes);
                string seedValueBase64 = Convert.ToBase64String(entry.Value);
                seedsObject[seedIdBase64] = seedValueBase64;
            }
            jsonObject["seeds"] = seedsObject;

            // Add initial and latest seed IDs
            byte[] initialSeedBytes = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(initialSeedBytes, _initialSeed);
            jsonObject["initialSeed"] = Convert.ToBase64String(initialSeedBytes);

            byte[] latestSeedBytes = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(latestSeedBytes, _latestSeed);
            jsonObject["latestSeed"] = Convert.ToBase64String(latestSeedBytes);

            // Add KDF salt
            jsonObject["kdfSalt"] = Convert.ToBase64String(_kdfSalt);

            // Serialize to JSON
            string json = JsonSerializer.Serialize(jsonObject, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            // Convert to bytes
            return Encoding.UTF8.GetBytes(json);
        }

        /// <summary>
        /// Securely destroys the key material.
        /// </summary>
        public void Destroy()
        {
            if (!_destroyed)
            {
                foreach (var entry in _seeds.ToList())
                {
                    CryptographicOperations.ZeroMemory(entry.Value);
                    _seeds.Remove(entry.Key);
                }

                CryptographicOperations.ZeroMemory(_kdfSalt);
                _destroyed = true;
            }
        }

        /// <summary>
        /// Checks if the key has been destroyed.
        /// </summary>
        /// <returns>True if the key has been destroyed, false otherwise</returns>
        public bool IsDestroyed()
        {
            return _destroyed;
        }

        /// <summary>
        /// Disposes of the key, securely destroying it.
        /// </summary>
        public void Dispose()
        {
            Destroy();
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Gets a copy of the raw key material. The caller is responsible for securely erasing this data when done.
        /// </summary>
        /// <returns>The raw key material</returns>
        public byte[] GetRawKey()
        {
            ThrowIfDestroyed();
            return GetRaw();
        }

        /// <summary>
        /// Gets the current master key.
        /// </summary>
        /// <returns>The current master key</returns>
        public DestroyableMasterkey Current()
        {
            ThrowIfDestroyed();
            return this;
        }

        /// <summary>
        /// Gets the initial revision of this key.
        /// </summary>
        /// <returns>The initial revision</returns>
        public int GetInitialRevision()
        {
            ThrowIfDestroyed();
            return _initialSeed;
        }

        /// <summary>
        /// Checks if this key has the given revision.
        /// </summary>
        /// <param name="revision">The revision to check</param>
        /// <returns>True if the key has the given revision, false otherwise</returns>
        public bool HasRevision(int revision)
        {
            ThrowIfDestroyed();
            return _seeds.ContainsKey(revision);
        }

        /// <summary>
        /// Gets the root directory ID for this masterkey.
        /// </summary>
        /// <returns>The root directory ID</returns>
        public byte[] GetRootDirId()
        {
            ThrowIfDestroyed();
            return KeyData(ROOT_DIRID_KDF_CONTEXT);
        }

        /// <summary>
        /// Gets the first revision of this key.
        /// </summary>
        /// <returns>The first revision</returns>
        public int GetFirstRevision()
        {
            ThrowIfDestroyed();
            return _initialSeed;
        }

        /// <summary>
        /// Gets a master key by its seed ID.
        /// </summary>
        /// <param name="seedId">The seed ID</param>
        /// <returns>The master key</returns>
        /// <exception cref="ArgumentException">If no key with the given seed ID exists</exception>
        public DestroyableMasterkey GetBySeedId(string seedId)
        {
            ThrowIfDestroyed();
            if (string.IsNullOrEmpty(seedId))
                throw new ArgumentNullException(nameof(seedId));

            try
            {
                byte[] seedIdBytes = Convert.FromBase64String(seedId);
                int seedIdInt = BinaryPrimitives.ReadInt32BigEndian(seedIdBytes);

                if (!_seeds.ContainsKey(seedIdInt))
                    throw new ArgumentException($"No seed with ID {seedId} exists", nameof(seedId));

                return this;
            }
            catch (FormatException ex)
            {
                throw new ArgumentException($"Invalid seed ID format: {seedId}", nameof(seedId), ex);
            }
        }

        private void ThrowIfDestroyed()
        {
            if (_destroyed)
            {
                throw new ObjectDisposedException(GetType().Name, "Masterkey is destroyed");
            }
        }
    }
}