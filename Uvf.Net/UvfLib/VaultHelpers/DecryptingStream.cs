/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/

// Copyright (c) Smart In Venture GmbH 2025 of the C# Porting


using UvfLib.Api;
using UvfLib.V3;
using System.Security.Cryptography;

namespace UvfLib.VaultHelpers
{
    /// <summary>
    /// Stream wrapper that decrypts Cryptomator V3 file format data as it's read.
    /// </summary>
    internal class DecryptingStream : Stream
    {
        private readonly Cryptor _cryptor;
        private readonly Stream _inputStream;
        private readonly bool _leaveOpen;
        private readonly FileHeader _fileHeader;
        private AesGcm _fileContentAesGcm; // Added to manage AesGcm instance
        private readonly byte[] _ciphertextChunkBuffer;
        private readonly Memory<byte> _plaintextChunkBuffer; // Buffer for decrypted chunk
        private int _plaintextBufferPosition = 0;
        private int _plaintextBufferLength = 0; // Actual valid data length in plaintext buffer
        private long _currentChunkNumber = 0; // Added for incrementing chunk number
        private bool _isDisposed = false;
        private bool _endOfStreamReached = false;

        private const int CIPHERTEXT_CHUNK_SIZE = V3.Constants.CHUNK_SIZE;
        private const int PLAINTEXT_CHUNK_SIZE = V3.Constants.PAYLOAD_SIZE;

        public DecryptingStream(Cryptor cryptor, Stream inputStream, bool leaveOpen)
        {
            _cryptor = cryptor ?? throw new ArgumentNullException(nameof(cryptor));
            _inputStream = inputStream ?? throw new ArgumentNullException(nameof(inputStream));
            _leaveOpen = leaveOpen;

            if (!_inputStream.CanRead) throw new ArgumentException("Input stream must be readable.", nameof(inputStream));
            if (_cryptor.FileHeaderCryptor() == null || _cryptor.FileContentCryptor() == null)
                throw new InvalidOperationException("Cryptor not fully initialized for file operations.");

            // Allocate buffers
            _ciphertextChunkBuffer = new byte[CIPHERTEXT_CHUNK_SIZE];
            _plaintextChunkBuffer = new Memory<byte>(new byte[PLAINTEXT_CHUNK_SIZE]);

            // 1. Read and decrypt header
            byte[] encryptedHeader = new byte[FileHeaderImpl.SIZE];
            int bytesRead = ReadExactly(_inputStream, encryptedHeader, 0, encryptedHeader.Length);
            if (bytesRead < encryptedHeader.Length)
            {
                throw new InvalidCiphertextException("Input stream ended before header could be fully read.");
            }
            _fileHeader = _cryptor.FileHeaderCryptor().DecryptHeader(encryptedHeader);

            // 1.1 Initialize AesGcm for file content
            var fileContentKeyBytes = ((V3.FileHeaderImpl)_fileHeader).GetContentKey().GetEncoded();
            _fileContentAesGcm = new AesGcm(fileContentKeyBytes);
            // Assuming DestroyableSecretKey.GetEncoded() returns a copy, the original within FileHeader is managed by its Dispose.
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            CheckDisposed();
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
            if (buffer.Length - offset < count) throw new ArgumentException("Invalid offset length combination.");

            int totalBytesRead = 0;
            while (count > 0)
            {
                // If plaintext buffer is exhausted, try reading and decrypting the next chunk
                if (_plaintextBufferPosition >= _plaintextBufferLength)
                {
                    if (!ReadAndDecryptNextChunk())
                    {
                        break; // End of stream reached, return what we have
                    }
                }

                // Copy available data from plaintext buffer to output buffer
                int bytesAvailable = _plaintextBufferLength - _plaintextBufferPosition;
                int bytesToCopy = Math.Min(count, bytesAvailable);
                _plaintextChunkBuffer.Slice(_plaintextBufferPosition, bytesToCopy).Span.CopyTo(buffer.AsSpan(offset, bytesToCopy));

                _plaintextBufferPosition += bytesToCopy;
                offset += bytesToCopy;
                count -= bytesToCopy;
                totalBytesRead += bytesToCopy;
            }

            return totalBytesRead;
        }

        private bool ReadAndDecryptNextChunk()
        {
            if (_endOfStreamReached) return false;

            // Read the next ciphertext chunk
            int bytesRead = ReadUpTo(_inputStream, _ciphertextChunkBuffer, 0, CIPHERTEXT_CHUNK_SIZE);

            // If nothing read, we're at the end
            if (bytesRead == 0)
            {
                _endOfStreamReached = true;
                _plaintextBufferLength = 0;
                _plaintextBufferPosition = 0;
                return false;
            }

            // We expect full chunks until the end. An incomplete chunk might indicate truncation.
            // GCM decryption requires the full chunk (nonce+ciphertext+tag).
            // If bytesRead < MIN_CIPHERTEXT_SIZE (nonce+tag), it's definitely an error.
            int minCiphertextSize = V3.Constants.GCM_NONCE_SIZE + V3.Constants.GCM_TAG_SIZE;
            if (bytesRead < minCiphertextSize)
            {
                _endOfStreamReached = true; // Prevent further reads
                throw new InvalidCiphertextException($"Incomplete ciphertext chunk read (read {bytesRead}, needed at least {minCiphertextSize}). Possible truncation or corruption.");
            }

            // Decrypt the chunk
            _plaintextBufferLength = ((V3.FileContentCryptorImpl)_cryptor.FileContentCryptor()).DecryptChunk(
                _fileContentAesGcm,
                new ReadOnlyMemory<byte>(_ciphertextChunkBuffer, 0, bytesRead),
                _plaintextChunkBuffer,
                _currentChunkNumber++, // Use and increment chunk number
                ((V3.FileHeaderImpl)_fileHeader).GetNonce() // Header nonce
            );

            // Calculate the actual plaintext length from the ciphertext length
            // _plaintextBufferLength = bytesRead - V3.Constants.GCM_NONCE_SIZE - V3.Constants.GCM_TAG_SIZE;
            _plaintextBufferPosition = 0;

            // If the last read was less than a full chunk, mark end of stream
            if (bytesRead < CIPHERTEXT_CHUNK_SIZE)
            {
                _endOfStreamReached = true;
            }

            return true;
        }

        // Helper to read exactly N bytes or throw
        private static int ReadExactly(Stream stream, byte[] buffer, int offset, int count)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = stream.Read(buffer, offset + totalRead, count - totalRead);
                if (read == 0) break; // End of stream
                totalRead += read;
            }
            return totalRead;
        }

        // Helper to read up to N bytes
        private static int ReadUpTo(Stream stream, byte[] buffer, int offset, int count)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = stream.Read(buffer, offset + totalRead, count - totalRead);
                if (read == 0) break; // End of stream
                totalRead += read;
            }
            return totalRead;
        }

        protected override void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                if (disposing)
                {
                    // Clean up resources
                    _fileContentAesGcm?.Dispose(); // Dispose AesGcm
                    _fileHeader?.Dispose(); // Dispose the content key within the header

                    if (!_leaveOpen)
                    {
                        _inputStream?.Dispose();
                    }
                }
                _isDisposed = true;
            }
            base.Dispose(disposing);
        }

        private void CheckDisposed()
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }
        }

        // --- Stream abstract members implementation ---

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException("DecryptingStream is non-seekable.");
        public override long Position
        {
            get => throw new NotSupportedException("DecryptingStream is non-seekable.");
            set => throw new NotSupportedException("DecryptingStream is non-seekable.");
        }

        public override void Flush() { /* No-op for read-only stream */ }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException("DecryptingStream is non-seekable.");
        public override void SetLength(long value) => throw new NotSupportedException("DecryptingStream length cannot be set.");
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException("DecryptingStream does not support writing.");

    }
}