/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/

// Copyright (c) Smart In Venture GmbH 2025 of the C# Porting


using CryptomatorLib.Api;

namespace CryptomatorLib.VaultHelpers
{
    /// <summary>
    /// Provides helper methods for directory and filename operations within a vault.
    /// </summary>
    internal static class VaultDirectoryHelper
    {
        // --- Directory Metadata Handling --- 

        public static byte[] EncryptDirectoryMetadataInternal(Cryptor cryptor, DirectoryMetadata metadata)
        {
            if (cryptor?.DirectoryContentCryptor() == null) throw new InvalidOperationException("Directory cryptor not available.");
            if (metadata == null) throw new ArgumentNullException(nameof(metadata));

            // Assuming the implementation handles potential type casting if needed
            return cryptor.DirectoryContentCryptor().EncryptDirectoryMetadata(metadata);
        }

        public static DirectoryMetadata DecryptDirectoryMetadataInternal(Cryptor cryptor, byte[] encryptedMetadata)
        {
            if (cryptor?.DirectoryContentCryptor() == null) throw new InvalidOperationException("Directory cryptor not available.");
            if (encryptedMetadata == null) throw new ArgumentNullException(nameof(encryptedMetadata));

            return cryptor.DirectoryContentCryptor().DecryptDirectoryMetadata(encryptedMetadata);
        }

        public static DirectoryMetadata CreateNewDirectoryMetadataInternal(Cryptor cryptor)
        {
            if (cryptor?.DirectoryContentCryptor() == null) throw new InvalidOperationException("Directory cryptor not available.");
            return cryptor.DirectoryContentCryptor().NewDirectoryMetadata();
        }

        // --- Filename Handling (Contextual) ---

        public static string EncryptFilenameInternal(Cryptor cryptor, DirectoryMetadata directoryMetadata, string plaintextFilename)
        {
            if (cryptor?.DirectoryContentCryptor() == null) throw new InvalidOperationException("Directory cryptor not available.");
            if (directoryMetadata == null) throw new ArgumentNullException(nameof(directoryMetadata));
            if (plaintextFilename == null) throw new ArgumentNullException(nameof(plaintextFilename));

            var nameEncryptor = cryptor.DirectoryContentCryptor().FileNameEncryptor(directoryMetadata);
            return nameEncryptor.Encrypt(plaintextFilename);
        }

        public static string DecryptFilenameInternal(Cryptor cryptor, DirectoryMetadata directoryMetadata, string encryptedFilename)
        {
            if (cryptor?.DirectoryContentCryptor() == null) throw new InvalidOperationException("Directory cryptor not available.");
            if (directoryMetadata == null) throw new ArgumentNullException(nameof(directoryMetadata));
            if (encryptedFilename == null) throw new ArgumentNullException(nameof(encryptedFilename));

            var nameDecryptor = cryptor.DirectoryContentCryptor().FileNameDecryptor(directoryMetadata);
            return nameDecryptor.Decrypt(encryptedFilename);
        }

        // --- Path Generation ---

        public static string GetDirectoryPathInternal(Cryptor cryptor, DirectoryMetadata directoryMetadata)
        {
            if (cryptor?.DirectoryContentCryptor() == null) throw new InvalidOperationException("Directory cryptor not available.");
            if (directoryMetadata == null) throw new ArgumentNullException(nameof(directoryMetadata));

            return cryptor.DirectoryContentCryptor().DirPath(directoryMetadata);
        }
    }
}