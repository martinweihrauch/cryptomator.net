/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/

// Copyright (c) Smart In Venture GmbH 2025 of the C# Porting


using System;
using System.Security.Cryptography;
using System.Text;
// using System.Text.Json; // No longer directly needed here for payload construction
using UvfLib.Api; // For UVFMasterkey for type hinting if needed
using UvfLib.Common; // For CryptographicOperations
using UvfLib.Jwe; // For JweVaultManager and UvfMasterkeyPayload
using UvfLib.V3; // For UVFMasterkeyImpl

namespace UvfLib.VaultHelpers
{
    /// <summary>
    /// Provides helper methods for vault key management (creation, password changes).
    /// Internal to hide implementation details from the Vault facade user.
    /// </summary>
    internal static class VaultKeyHelper
    {
        // private static readonly RandomNumberGenerator CsPrng = RandomNumberGenerator.Create(); // Not used if key gen is in UVFMasterkeyImpl

        /// <summary>
        /// Creates the encrypted master key file content for a new vault.
        /// </summary>
        public static byte[] CreateNewVaultKeyFileContentInternal(string password, byte[]? pepper)
        {
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));
            // Pepper usage remains a point for future consideration if needed before PBKDF2.

            byte[]? masterKeyBytes = null;
            byte[]? hmacKeyBytes = null;
            UVFMasterkey? uvfKey = null;

            try
            {
                // 1. Generate new raw key material
                masterKeyBytes = RandomNumberGenerator.GetBytes(32); // AES-256 key
                hmacKeyBytes = RandomNumberGenerator.GetBytes(32);   // HMAC-SHA256 key

                // 2. Create a UVFMasterkeyImpl instance from the raw keys.
                // This instance will represent a new master key set.
                // We use the more explicit constructor or static factory method if available.
                // Using the constructor that takes individual keys:
                uvfKey = new UVFMasterkeyImpl(masterKeyBytes, hmacKeyBytes, seeds: null, kdfSalt: null, rootDirIdBase64: null, initialSeed: 0, latestSeed: 0);
                // Or, using a static factory like UVFMasterkeyImpl.CreateFromRaw(masterKeyBytes, hmacKeyBytes);
                // depending on which is preferred and how it initializes default seeds/versions internally.

                // 3. Get the UvfMasterkeyPayload from the new UVFMasterkeyImpl instance.
                // This requires UVFMasterkeyImpl to have the ToMasterkeyPayload() method.
                UvfMasterkeyPayload payload = ((UVFMasterkeyImpl)uvfKey).ToMasterkeyPayload();
            
                // 4. Create the JWE string using JweVaultManager
                string jweString = JweVaultManager.CreateVault(payload, password);
                return Encoding.UTF8.GetBytes(jweString);
            }
            finally
            {
                // Ensure sensitive key material is zeroed out
                if (masterKeyBytes != null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(masterKeyBytes);
                if (hmacKeyBytes != null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(hmacKeyBytes);
                // The UVFMasterkeyImpl instance should handle zeroing its internal keys upon disposal if it implements IDisposable.
                (uvfKey as IDisposable)?.Dispose(); 
            }
        }

        /// <summary>
        /// Changes the password for an existing vault's master key file content.
        /// </summary>
        public static byte[] ChangeVaultPasswordInternal(byte[] encryptedKeyFileContent, string oldPassword, string newPassword, byte[]? pepper)
        {
            if (encryptedKeyFileContent == null || encryptedKeyFileContent.Length == 0) throw new ArgumentNullException(nameof(encryptedKeyFileContent));
            if (string.IsNullOrEmpty(oldPassword)) throw new ArgumentNullException(nameof(oldPassword));
            if (string.IsNullOrEmpty(newPassword)) throw new ArgumentNullException(nameof(newPassword));
            // Pepper usage remains for future consideration.

            string jweStringOld = Encoding.UTF8.GetString(encryptedKeyFileContent);

            // 1. Load the existing payload using the old password
            // LoadVaultPayload returns the UvfMasterkeyPayload directly.
            UvfMasterkeyPayload existingPayload = JweVaultManager.LoadVaultPayload(jweStringOld, oldPassword);

            // 2. Create a new JWE vault with the existing payload and the new password
            // This re-encrypts the same master key material with a new KEK derived from the new password.
            string jweStringNew = JweVaultManager.CreateVault(existingPayload, newPassword);

            return Encoding.UTF8.GetBytes(jweStringNew);
        }
    }
}