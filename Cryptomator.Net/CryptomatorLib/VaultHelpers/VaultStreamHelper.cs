using System;
using System.IO;
using CryptomatorLib.Api;

namespace CryptomatorLib.VaultHelpers
{
    /// <summary>
    /// Provides helper methods for creating encrypting/decrypting streams.
    /// </summary>
    internal static class VaultStreamHelper
    {
        public static Stream GetEncryptingStreamInternal(Cryptor cryptor, Stream outputStream, bool leaveOpen)
        {
            // Validate arguments
            if (cryptor == null) throw new ArgumentNullException(nameof(cryptor));
            if (outputStream == null) throw new ArgumentNullException(nameof(outputStream));
            if (!outputStream.CanWrite) throw new ArgumentException("Output stream must be writable", nameof(outputStream));

            return new EncryptingStream(cryptor, outputStream, leaveOpen);
        }

        public static Stream GetDecryptingStreamInternal(Cryptor cryptor, Stream inputStream, bool leaveOpen)
        {
            // Validate arguments
            if (cryptor == null) throw new ArgumentNullException(nameof(cryptor));
            if (inputStream == null) throw new ArgumentNullException(nameof(inputStream));
            if (!inputStream.CanRead) throw new ArgumentException("Input stream must be readable", nameof(inputStream));

            // Use the implemented DecryptingStream class
            return new DecryptingStream(cryptor, inputStream, leaveOpen);
        }
    }
}