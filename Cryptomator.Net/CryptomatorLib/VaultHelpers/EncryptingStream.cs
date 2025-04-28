using System;
using System.IO;
using System.Security.Cryptography;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using CryptomatorLib.V3;
using System.Buffers;

namespace CryptomatorLib.VaultHelpers
{
    /// <summary>
    /// Stream wrapper that encrypts data using Cryptomator V3 file format as it's written.
    /// </summary>
    internal class EncryptingStream : Stream
    {
        private readonly Cryptor _cryptor;
        private readonly Stream _outputStream;
        private readonly bool _leaveOpen;
        private readonly FileHeader _fileHeader;
        private readonly byte[] _cleartextChunkBuffer;
        private int _bufferPosition = 0;
        private bool _headerWritten = false;
        private bool _isDisposed = false;

        private const int CLEARTEXT_CHUNK_SIZE = V3.Constants.PAYLOAD_SIZE;
        private readonly Memory<byte> _ciphertextChunkBuffer; // Reusable buffer for encrypted output

        public EncryptingStream(Cryptor cryptor, Stream outputStream, bool leaveOpen)
        {
            _cryptor = cryptor ?? throw new ArgumentNullException(nameof(cryptor));
            _outputStream = outputStream ?? throw new ArgumentNullException(nameof(outputStream));
            _leaveOpen = leaveOpen;

            if (!_outputStream.CanWrite) throw new ArgumentException("Output stream must be writable.", nameof(outputStream));
            if (_cryptor.FileHeaderCryptor() == null || _cryptor.FileContentCryptor() == null)
                throw new InvalidOperationException("Cryptor not fully initialized for file operations.");

            // 1. Create header
            _fileHeader = _cryptor.FileHeaderCryptor().Create();

            // Allocate buffers
            _cleartextChunkBuffer = new byte[CLEARTEXT_CHUNK_SIZE];
            _ciphertextChunkBuffer = new Memory<byte>(new byte[_cryptor.FileContentCryptor().CiphertextChunkSize()]);
        }

        private void EnsureHeaderWritten()
        {
            if (!_headerWritten)
            {
                Memory<byte> encryptedHeaderMemory = _cryptor.FileHeaderCryptor().EncryptHeader(_fileHeader);
                byte[] encryptedHeaderBytes = encryptedHeaderMemory.ToArray();
                _outputStream.Write(encryptedHeaderBytes, 0, encryptedHeaderBytes.Length);
                _headerWritten = true;
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            CheckDisposed();
            EnsureHeaderWritten();

            int bytesToProcess = count;
            int currentOffset = offset;

            while (bytesToProcess > 0)
            {
                int bytesToCopy = Math.Min(bytesToProcess, CLEARTEXT_CHUNK_SIZE - _bufferPosition);
                Buffer.BlockCopy(buffer, currentOffset, _cleartextChunkBuffer, _bufferPosition, bytesToCopy);
                _bufferPosition += bytesToCopy;
                currentOffset += bytesToCopy;
                bytesToProcess -= bytesToCopy;

                // If buffer is full, encrypt and write chunk
                if (_bufferPosition == CLEARTEXT_CHUNK_SIZE)
                {
                    EncryptAndWriteChunk(_cleartextChunkBuffer.AsMemory(0, CLEARTEXT_CHUNK_SIZE));
                    _bufferPosition = 0; // Reset buffer
                }
            }
        }

        private void EncryptAndWriteChunk(ReadOnlyMemory<byte> cleartextChunk)
        {
            _cryptor.FileContentCryptor().EncryptChunk(cleartextChunk, _ciphertextChunkBuffer, 0, _fileHeader);
            _outputStream.Write(_ciphertextChunkBuffer.Span);
        }

        public override void Flush()
        {
            CheckDisposed();
            EnsureHeaderWritten(); // Ensure header is written even if no data follows

            // Encrypt and write any remaining data in the buffer as the final chunk
            if (_bufferPosition > 0)
            {
                EncryptAndWriteChunk(_cleartextChunkBuffer.AsMemory(0, _bufferPosition));
                _bufferPosition = 0; // Clear buffer after flushing
            }

            _outputStream.Flush(); // Flush the underlying stream
        }

        protected override void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                if (disposing)
                {
                    try
                    {
                        // Ensure final chunk is written
                        Flush();
                    }
                    finally
                    {
                        // Clean up resources
                        _fileHeader?.Dispose(); // Dispose the content key within the header

                        if (!_leaveOpen)
                        {
                            _outputStream?.Dispose();
                        }
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

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException("EncryptingStream is non-seekable.");
        public override long Position
        {
            get => throw new NotSupportedException("EncryptingStream is non-seekable.");
            set => throw new NotSupportedException("EncryptingStream is non-seekable.");
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException("EncryptingStream does not support reading.");
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException("EncryptingStream is non-seekable.");
        public override void SetLength(long value) => throw new NotSupportedException("EncryptingStream length cannot be set.");

    }
}