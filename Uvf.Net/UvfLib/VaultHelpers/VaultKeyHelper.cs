/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/

// Copyright (c) Smart In Venture GmbH 2025 of the C# Porting


using System.Security.Cryptography;
using UvfLib.Api;
using UvfLib.Common; // For MasterkeyFileAccess, MasterkeyFile, CryptographicOperations

namespace UvfLib.VaultHelpers
{
    /// <summary>
    /// Provides helper methods for vault key management (creation, password changes).
    /// Internal to hide implementation details from the Vault facade user.
    /// </summary>
    internal static class VaultKeyHelper
    {
        private static readonly RandomNumberGenerator CsPrng = RandomNumberGenerator.Create();
        private const int CURRENT_VAULT_FORMAT_VERSION = 8; // Assuming Cryptomator Vault Format Version 8
        // Default Scrypt parameters (match MasterkeyFileAccess defaults if possible, check implementation)
        // Using values from MasterkeyFileAccess internal constants for now
        private const int SCRYPT_COST_DEFAULT = 1 << 17; // 131072
        private const int SCRYPT_BLOCK_SIZE_DEFAULT = 8;
        private const int SCRYPT_PARALLELIZATION_DEFAULT = 1;

        /// <summary>
        /// Creates the encrypted master key file content for a new vault.
        /// </summary>
        public static byte[] CreateNewVaultKeyFileContentInternal(string password, byte[]? pepper)
        {
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));
            byte[] effectivePepper = pepper ?? Array.Empty<byte>(); // Use provided pepper or default empty

            PerpetualMasterkey? masterkey = null;
            byte[]? rawKeyBytes = null; // Declare outside try for finally block access
            try
            {
                // 1. Generate a new random PerpetualMasterkey
                // Generate random key bytes first
                rawKeyBytes = new byte[PerpetualMasterkey.SubkeyLengthBytes * 2];
                CsPrng.GetBytes(rawKeyBytes);
                masterkey = new PerpetualMasterkey(rawKeyBytes);
                // Raw key bytes are copied internally by PerpetualMasterkey constructor

                // 2. Create MasterkeyFileAccess instance using effective pepper
                var keyAccessor = new MasterkeyFileAccess(effectivePepper, CsPrng);

                // 3. Lock the key with the password to create the MasterkeyFile structure
                // Provide default Scrypt parameters - Lock signature needs costParam
                // Assuming Lock method handles block size and parallelism internally based on MasterkeyFile defaults
                MasterkeyFile masterkeyFile = keyAccessor.Lock(masterkey, password, CURRENT_VAULT_FORMAT_VERSION, SCRYPT_COST_DEFAULT);

                // 4. Serialize the MasterkeyFile to JSON bytes
                byte[] encryptedKeyFileContent = masterkeyFile.ToJson();

                return encryptedKeyFileContent;
            }
            finally
            {
                // Ensure sensitive key material is disposed/zeroed
                masterkey?.Dispose();
                // Zero out the initially generated bytes buffer if it exists
                if (rawKeyBytes != null)
                {
                    // Fully qualify the call to resolve ambiguity
                    UvfLib.Common.CryptographicOperations.ZeroMemory(rawKeyBytes);
                }
            }
        }

        /// <summary>
        /// Changes the password for an existing vault's master key file content.
        /// </summary>
        public static byte[] ChangeVaultPasswordInternal(byte[] encryptedKeyFileContent, string oldPassword, string newPassword, byte[]? pepper)
        {
            if (encryptedKeyFileContent == null) throw new ArgumentNullException(nameof(encryptedKeyFileContent));
            if (string.IsNullOrEmpty(oldPassword)) throw new ArgumentNullException(nameof(oldPassword));
            if (string.IsNullOrEmpty(newPassword)) throw new ArgumentNullException(nameof(newPassword));
            byte[] effectivePepper = pepper ?? Array.Empty<byte>(); // Use provided pepper or default empty

            // 1. Create MasterkeyFileAccess instance using effective pepper
            var keyAccessor = new MasterkeyFileAccess(effectivePepper, CsPrng);

            // 2. Parse the existing content
            MasterkeyFile masterkeyFile = MasterkeyFile.FromJson(encryptedKeyFileContent);

            // 3. Use the ChangePassphrase method (which internally unlocks with old, locks with new)
            // ChangePassphrase itself needs pepper for the Unlock and Lock steps internally
            // Assuming MasterkeyFileAccess uses its instance pepper for this.
            MasterkeyFile updatedMasterkeyFile = keyAccessor.ChangePassphrase(masterkeyFile, oldPassword, newPassword);

            // 4. Serialize the updated MasterkeyFile to JSON bytes
            byte[] newEncryptedKeyFileContent = updatedMasterkeyFile.ToJson();

            return newEncryptedKeyFileContent;

            // Note: Keys inside ChangePassphrase should ideally be disposed automatically by that method.
        }
    }
}