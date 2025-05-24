using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Jose;
using UvfLib.Api;

namespace UvfLib.Jwe
{
    /// <summary>
    /// Manages JWE-formatted vault files (vault.uvf).
    /// </summary>
    public static class JweVaultManager
    {
        private const JweAlgorithm KeyManagementAlgorithm = JweAlgorithm.PBES2_HS512_A256KW;
        private const JweEncryption ContentEncryptionAlgorithm = JweEncryption.A256GCM;
        private const int DefaultPbkdf2Iterations = 262144; // A reasonable default, higher is better.
        private const int Pbkdf2SaltSizeBytes = 16; // 128 bits for salt

        /// <summary>
        /// Creates a JWE-_formatted string representing an encrypted vault.uvf file.
        /// </summary>
        /// <param name="payload">The UVF masterkey payload to encrypt.</param>
        /// <param name="password">The password to protect the vault.</param>
        /// <param name="pbkdf2Iterations">The number of iterations for PBKDF2. Defaults to a secure value.</param>
        /// <returns>A JWE compact serialization string.</returns>
        public static string CreateVault(UvfMasterkeyPayload payload, string password, int pbkdf2Iterations = DefaultPbkdf2Iterations)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));
            if (pbkdf2Iterations < 10000) throw new ArgumentException("PBKDF2 iteration count is too low.", nameof(pbkdf2Iterations));

            string payloadJson = JsonSerializer.Serialize(payload);

            // jose-jwt handles salt generation internally for PBES2 if not provided via extraHeaders.
            // However, to be explicit and align with the provided test vault, we can specify p2s and p2c.
            byte[] salt = RandomNumberGenerator.GetBytes(Pbkdf2SaltSizeBytes);

            var extraHeaders = new Dictionary<string, object>
            {
                { "p2s", Base64Url.Encode(salt) },
                { "p2c", pbkdf2Iterations },
                { "uvf.spec.version", payload.UvfSpecVersion } // Include in protected header
            };

            return JWT.Encode(payloadJson, password, KeyManagementAlgorithm, ContentEncryptionAlgorithm, extraHeaders: extraHeaders);
        }

        /// <summary>
        /// Loads and decrypts a UVF masterkey from a JWE-formatted string.
        /// </summary>
        /// <param name="jweString">The JWE compact serialization string (content of vault.uvf).</param>
        /// <param name="password">The password to decrypt the vault.</param>
        /// <returns>A UVFMasterkey instance.</returns>
        /// <exception cref="ArgumentNullException">If jweString or password is null/empty.</exception>
        /// <exception cref="InvalidOperationException">If decryption fails or payload is invalid.</exception>
        /// <exception cref="JoseException">If JWE processing fails (e.g., wrong password, malformed token).</exception>
        public static UvfMasterkeyPayload LoadVaultPayload(string jweString, string password)
        {
            if (string.IsNullOrEmpty(jweString)) throw new ArgumentNullException(nameof(jweString));
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));

            string decryptedJsonPayload = JWT.Decode(jweString, password);

            if (string.IsNullOrEmpty(decryptedJsonPayload))
            {
                throw new InvalidOperationException("Decrypted JWE payload was null or empty.");
            }

            var payload = JsonSerializer.Deserialize<UvfMasterkeyPayload>(decryptedJsonPayload);
            if (payload == null)
            {
                throw new InvalidOperationException("Failed to deserialize the JWE payload into UvfMasterkeyPayload.");
            }
            return payload;
        }
    }
} 