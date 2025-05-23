using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using UvfLib.Api;
using UvfLib.Common;

namespace UvfLib.V3
{
    /// <summary>
    /// Implementation of the FileContentCryptor interface for v3 format.
    /// </summary>
    public sealed class FileContentCryptorImpl : FileContentCryptor
    {
        private readonly RandomNumberGenerator _random;
        private readonly RevolvingMasterkey _revolvingMasterkey;

        /// <summary>
        /// Creates a new file content cryptor.
        /// </summary>
        /// <param name="revolvingMasterkey">The revolving masterkey</param>
        /// <param name="random">The random number generator</param>
        public FileContentCryptorImpl(RevolvingMasterkey revolvingMasterkey, RandomNumberGenerator random)
        {
            _revolvingMasterkey = revolvingMasterkey ?? throw new ArgumentNullException(nameof(revolvingMasterkey));
            _random = random ?? throw new ArgumentNullException(nameof(random));
        }

        /// <summary>
        /// Determines whether authentication can be skipped for performance reasons.
        /// </summary>
        /// <returns>Always false for GCM mode</returns>
        public bool CanSkipAuthentication()
        {
            return false; // Authentication is integral part of GCM
        }

        /// <summary>
        /// Gets the size in bytes of a cleartext chunk.
        /// </summary>
        /// <returns>The cleartext chunk size</returns>
        public int CleartextChunkSize()
        {
            return Constants.PAYLOAD_SIZE;
        }

        /// <summary>
        /// Gets the size in bytes of a ciphertext chunk.
        /// </summary>
        /// <returns>The ciphertext chunk size</returns>
        public int CiphertextChunkSize()
        {
            return Constants.CHUNK_SIZE;
        }

        /// <summary>
        /// Calculates the cleartext size based on the ciphertext size.
        /// </summary>
        /// <param name="ciphertextSize">The size of the ciphertext in bytes</param>
        /// <returns>The estimated cleartext size in bytes</returns>
        public long CleartextSize(long ciphertextSize)
        {
            // Get header size
            int headerSize = HeaderSize();

            // Basic validation: ciphertext must be at least header size
            if (ciphertextSize < headerSize)
            {
                // Consider throwing ArgumentException or returning 0 based on expected behavior for invalid size.
                // Java tests imply 0 is expected for sizes slightly larger than header but too small for a chunk payload.
                // Let's return 0 for sizes smaller than header + nonce + tag, matching Java test expectation indirectly.
                if (ciphertextSize < headerSize + Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE)
                    return 0;
                // Otherwise, it's an invalid size between header and smallest possible chunk.
                throw new ArgumentException("Ciphertext size is too small to contain valid data.", nameof(ciphertextSize));
            }

            // Subtract header size before chunk calculation
            long effectiveCiphertextSize = ciphertextSize - headerSize;
            long cleartextSize = 0;

            // Calculate number of complete chunks from the effective size
            long numCompleteChunks = Math.DivRem(effectiveCiphertextSize, Constants.CHUNK_SIZE, out long remainder);

            // Add size of complete chunks
            cleartextSize += numCompleteChunks * Constants.PAYLOAD_SIZE;

            // Handle the remainder (partial last chunk) if it exists
            // A valid remainder must contain at least nonce + tag
            if (remainder >= Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE)
            {
                // Payload size is the remainder minus overhead
                cleartextSize += remainder - Constants.GCM_NONCE_SIZE - Constants.GCM_TAG_SIZE;
            }
            else if (remainder > 0)
            {
                // Remainder exists but is too small to be a valid chunk (contains only nonce/tag or less)
                // This indicates an invalid ciphertext size according to the chunk structure.
                // Let's return 0 to match Java test expectations for sizes like 39 (after header)
                return 0;
                // Alternatively, throw: throw new ArgumentException("Invalid ciphertext size: remainder is too small.", nameof(ciphertextSize));
            }

            return cleartextSize;
        }

        /// <summary>
        /// Gets the header size in bytes.
        /// </summary>
        /// <returns>The header size in bytes</returns>
        public int HeaderSize()
        {
            return FileHeaderImpl.SIZE;
        }

        /// <summary>
        /// Encrypts a chunk of data.
        /// </summary>
        /// <param name="cleartextChunk">The chunk to encrypt</param>
        /// <param name="chunkNumber">The number of the chunk in the stream</param>
        /// <param name="header">The file header</param>
        /// <returns>The encrypted chunk</returns>
        public Memory<byte> EncryptChunk(ReadOnlyMemory<byte> cleartextChunk, long chunkNumber, FileHeader header)
        {
            var ciphertextChunk = new Memory<byte>(new byte[Constants.CHUNK_SIZE]);
            EncryptChunk(cleartextChunk, ciphertextChunk, chunkNumber, header);
            return ciphertextChunk;
        }

        /// <summary>
        /// Encrypts a chunk of data.
        /// </summary>
        /// <param name="cleartextChunk">The chunk to encrypt</param>
        /// <param name="ciphertextChunk">The buffer to store the encrypted chunk</param>
        /// <param name="chunkNumber">The number of the chunk in the stream</param>
        /// <param name="header">The file header</param>
        public void EncryptChunk(ReadOnlyMemory<byte> cleartextChunk, Memory<byte> ciphertextChunk, long chunkNumber, FileHeader header)
        {
            ValidateEncryptionParameters(cleartextChunk, ciphertextChunk, header);

            FileHeaderImpl headerImpl = FileHeaderImpl.Cast(header);

            // Generate nonce (IV)
            byte[] nonce = new byte[Constants.GCM_NONCE_SIZE];
            _random.GetBytes(nonce);

            // Debug: Log nonce values
            Debug.WriteLine($"Encrypting chunk {chunkNumber} with nonce: {BitConverter.ToString(nonce)}");

            // Copy nonce to beginning of ciphertext
            nonce.CopyTo(ciphertextChunk);

            // Prepare AAD: chunk number + header nonce
            byte[] headerNonce = headerImpl.GetNonce();
            byte[] chunkNumberBytes = ByteBuffers.LongToByteArray(chunkNumber);
            byte[] aad = ByteBuffers.Concat(chunkNumberBytes, headerNonce);

            // Debug: Log AAD
            Debug.WriteLine($"Encrypting chunk {chunkNumber} with AAD length: {aad.Length}");

            try
            {
                // Get content key, create a copy for independent use
                var contentKeyBytes = headerImpl.GetContentKey().GetEncoded();
                using var contentKey = new DestroyableSecretKey(contentKeyBytes, headerImpl.GetContentKey().Algorithm);

                // Encrypt using AES-GCM
                using var aesGcm = new AesGcm(contentKey.GetEncoded());

                // Encrypt in-place
                byte[] tag = new byte[Constants.GCM_TAG_SIZE];
                aesGcm.Encrypt(
                    nonce,
                    cleartextChunk.Span,
                    ciphertextChunk.Slice(Constants.GCM_NONCE_SIZE, cleartextChunk.Length).Span,
                    tag,
                    aad);

                // Debug: Log tag
                Debug.WriteLine($"Encryption tag for chunk {chunkNumber}: {BitConverter.ToString(tag)}");

                // Copy tag to output
                tag.CopyTo(ciphertextChunk.Slice(Constants.GCM_NONCE_SIZE + cleartextChunk.Length, Constants.GCM_TAG_SIZE));
            }
            catch (CryptographicException ex)
            {
                Debug.WriteLine($"Encryption failed for chunk {chunkNumber}: {ex.Message}");
                throw new CryptoException("Encryption failed", ex);
            }
            finally
            {
                // Clean up sensitive data
                UvfLib.Common.CryptographicOperations.ZeroMemory(nonce);
                UvfLib.Common.CryptographicOperations.ZeroMemory(aad);
            }
        }

        /// <summary>
        /// Decrypts a chunk of data.
        /// </summary>
        /// <param name="ciphertextChunk">The encrypted chunk</param>
        /// <param name="chunkNumber">The number of the chunk in the stream</param>
        /// <param name="header">The file header</param>
        /// <param name="authenticate">Whether to authenticate the chunk (must be true for GCM)</param>
        /// <returns>The decrypted chunk</returns>
        /// <exception cref="AuthenticationFailedException">If authentication fails</exception>
        public Memory<byte> DecryptChunk(ReadOnlyMemory<byte> ciphertextChunk, long chunkNumber, FileHeader header, bool authenticate)
        {
            ValidateDecryptionParameters(ciphertextChunk, Memory<byte>.Empty, header, authenticate);

            // Allocate buffer for plaintext - max size is payload size
            var cleartextChunk = new Memory<byte>(new byte[Constants.PAYLOAD_SIZE]);

            // Decrypt
            DecryptChunk(ciphertextChunk, cleartextChunk, chunkNumber, header, authenticate);

            return cleartextChunk;
        }

        /// <summary>
        /// Decrypts a chunk of data.
        /// </summary>
        /// <param name="ciphertextChunk">The encrypted chunk data</param>
        /// <param name="cleartextChunk">The buffer to store the decrypted chunk</param>
        /// <param name="chunkNumber">The chunk number</param>
        /// <param name="header">The file header</param>
        /// <param name="authenticate">Whether to authenticate the data</param>
        /// <exception cref="ArgumentException">If the ciphertext chunk is too small</exception>
        /// <exception cref="AuthenticationFailedException">If the data fails authentication</exception>
        public int DecryptChunk(ReadOnlyMemory<byte> ciphertextChunk, Memory<byte> cleartextChunk, long chunkNumber, FileHeader header, bool authenticate)
        {
            ValidateDecryptionParameters(ciphertextChunk, cleartextChunk, header, authenticate);

            FileHeaderImpl headerImpl = FileHeaderImpl.Cast(header);

            // Extract nonce from beginning of ciphertext
            byte[] nonce = new byte[Constants.GCM_NONCE_SIZE];
            ciphertextChunk.Slice(0, Constants.GCM_NONCE_SIZE).CopyTo(nonce);

            // Calculate payload size (total - nonce - tag)
            int payloadSize = ciphertextChunk.Length - Constants.GCM_NONCE_SIZE - Constants.GCM_TAG_SIZE;
            if (payloadSize < 0)
            {
                throw new ArgumentException("Ciphertext chunk is too small to contain nonce and tag.", nameof(ciphertextChunk));
            }

            // Check if the provided cleartext buffer is large enough
            if (cleartextChunk.Length < payloadSize)
            {
                throw new ArgumentException("Provided cleartext buffer is too small for the decrypted payload.", nameof(cleartextChunk));
            }

            // Extract tag from the end of ciphertext
            byte[] tag = new byte[Constants.GCM_TAG_SIZE];
            ciphertextChunk.Slice(ciphertextChunk.Length - Constants.GCM_TAG_SIZE, Constants.GCM_TAG_SIZE).CopyTo(tag);

            // Prepare AAD if authentication is enabled
            byte[] aad = Array.Empty<byte>();
            if (authenticate && !CanSkipAuthentication())
            {
                byte[] headerNonce = headerImpl.GetNonce();
                byte[] chunkNumberBytes = ByteBuffers.LongToByteArray(chunkNumber);
                aad = ByteBuffers.Concat(chunkNumberBytes, headerNonce);
                Debug.WriteLine($"Decrypting chunk {chunkNumber} with AAD length: {aad.Length}");
                Debug.WriteLine($"Decrypting chunk {chunkNumber} with size: {ciphertextChunk.Length}");
                Debug.WriteLine($"Decrypting chunk {chunkNumber} with nonce: {BitConverter.ToString(nonce)}");
                Debug.WriteLine($"Decryption tag for chunk {chunkNumber}: {BitConverter.ToString(tag)}");
            }
            else if (authenticate)
            {
                // Should not happen with GCM, as CanSkipAuthentication is false
                throw new InvalidOperationException("Authentication required but skipping is not supported.");
            }

            try
            {
                // Get content key from header
                var contentKeyBytes = headerImpl.GetContentKey().GetEncoded();
                using var contentKey = new DestroyableSecretKey(contentKeyBytes, headerImpl.GetContentKey().Algorithm);

                // Decrypt using AES-GCM
                using var aesGcm = new AesGcm(contentKey.GetEncoded());

                aesGcm.Decrypt(
                    nonce,
                    ciphertextChunk.Slice(Constants.GCM_NONCE_SIZE, payloadSize).Span, // Ciphertext payload
                    tag,
                    cleartextChunk.Slice(0, payloadSize).Span, // Destination for plaintext
                    aad);

                // Return the actual number of bytes decrypted
                return payloadSize;
            }
            catch (CryptographicException ex)
            {
                // Authentication likely failed
                Debug.WriteLine($"Decryption failed for chunk {chunkNumber}: {ex.Message}");
                throw new AuthenticationFailedException("Chunk decryption failed, possibly due to invalid authentication tag.", ex);
            }
            finally
            {
                // Clean up sensitive data
                UvfLib.Common.CryptographicOperations.ZeroMemory(nonce);
                UvfLib.Common.CryptographicOperations.ZeroMemory(aad);
                UvfLib.Common.CryptographicOperations.ZeroMemory(tag);
            }
        }

        private static void ValidateEncryptionParameters(ReadOnlyMemory<byte> cleartextChunk, Memory<byte> ciphertextChunk, FileHeader header)
        {
            if (header == null)
            {
                throw new ArgumentNullException(nameof(header));
            }

            if (cleartextChunk.IsEmpty)
            {
                throw new ArgumentException("Cleartext chunk must not be empty", nameof(cleartextChunk));
            }

            if (cleartextChunk.Length > Constants.PAYLOAD_SIZE)
            {
                throw new ArgumentException($"Cleartext chunk size exceeds maximum of {Constants.PAYLOAD_SIZE} bytes", nameof(cleartextChunk));
            }

            if (ciphertextChunk.Length < Constants.CHUNK_SIZE)
            {
                throw new ArgumentException($"Ciphertext chunk buffer must be at least {Constants.CHUNK_SIZE} bytes", nameof(ciphertextChunk));
            }
        }

        private static void ValidateDecryptionParameters(ReadOnlyMemory<byte> ciphertextChunk, Memory<byte> cleartextChunk, FileHeader header, bool authenticate)
        {
            if (header == null)
            {
                throw new ArgumentNullException(nameof(header));
            }

            // For GCM, authentication is mandatory
            if (!authenticate)
            {
                throw new UnsupportedOperationException("Authentication cannot be disabled for GCM mode");
            }

            // Minimal size check
            if (ciphertextChunk.Length < Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE)
            {
                throw new ArgumentException($"Ciphertext chunk must be at least {Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE} bytes", nameof(ciphertextChunk));
            }

            // Maximum size check
            if (ciphertextChunk.Length > Constants.CHUNK_SIZE)
            {
                throw new ArgumentException($"Ciphertext chunk must not exceed {Constants.CHUNK_SIZE} bytes", nameof(ciphertextChunk));
            }

            // Skip cleartext buffer check if buffer is empty (case when we're returning a new buffer)
            if (!cleartextChunk.IsEmpty)
            {
                // Calculate payload size (total - nonce - tag)
                int payloadSize = ciphertextChunk.Length - Constants.GCM_NONCE_SIZE - Constants.GCM_TAG_SIZE;

                // Ensure cleartext buffer is large enough
                if (cleartextChunk.Length < payloadSize)
                {
                    throw new ArgumentException($"Cleartext chunk buffer must be at least {payloadSize} bytes", nameof(cleartextChunk));
                }
            }
        }
    }

    /// <summary>
    /// Exception thrown when an operation is not supported.
    /// </summary>
    public class UnsupportedOperationException : Exception
    {
        /// <summary>
        /// Creates a new UnsupportedOperationException.
        /// </summary>
        public UnsupportedOperationException() : base() { }

        /// <summary>
        /// Creates a new UnsupportedOperationException with the specified message.
        /// </summary>
        /// <param name="message">The exception message</param>
        public UnsupportedOperationException(string message) : base(message) { }

        /// <summary>
        /// Creates a new UnsupportedOperationException with the specified message and inner exception.
        /// </summary>
        /// <param name="message">The exception message</param>
        /// <param name="innerException">The inner exception</param>
        public UnsupportedOperationException(string message, Exception innerException) : base(message, innerException) { }
    }
}