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
using System.Security.Cryptography;
using System.Buffers.Binary;
#if DEBUG
using System.Diagnostics; // For Stopwatch
#endif

namespace UvfLib.VaultHelpers
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
        private AesGcm _fileContentAesGcm;
        private readonly RandomNumberGenerator _random;
        private readonly byte[] _cleartextChunkBuffer;
        private readonly byte[] _perChunkNonce;
        private readonly byte[] _aadBuffer; // Buffer for AAD
        private int _bufferPosition = 0;
        private long _currentChunkNumber = 0;
        private bool _headerWritten = false;
        private bool _isDisposed = false;

#if DEBUG
        private readonly PerformanceMetrics _metrics;
#endif

        private const int CLEARTEXT_CHUNK_SIZE = V3.Constants.PAYLOAD_SIZE; // Reverted to use constant
        private readonly Memory<byte> _ciphertextChunkBuffer; // Reusable buffer for encrypted output

        public EncryptingStream(Cryptor cryptor, Stream outputStream, bool leaveOpen)
        {
            _cryptor = cryptor ?? throw new ArgumentNullException(nameof(cryptor));
            _outputStream = outputStream ?? throw new ArgumentNullException(nameof(outputStream));
            _leaveOpen = leaveOpen;
            _random = RandomNumberGenerator.Create();
            _perChunkNonce = new byte[V3.Constants.GCM_NONCE_SIZE];

#if DEBUG
            _metrics = new PerformanceMetrics("EncryptingStream")
            {
                Operation1Name = "NonceGen",
                Operation2Name = "AADPrep",
                Operation3Name = "EncryptOp",
                Operation4Name = "StreamWrite"
            };
#endif

            if (!_outputStream.CanWrite) throw new ArgumentException("Output stream must be writable.", nameof(outputStream));
            if (_cryptor.FileHeaderCryptor() == null || _cryptor.FileContentCryptor() == null)
                throw new InvalidOperationException("Cryptor not fully initialized for file operations.");

            _fileHeader = _cryptor.FileHeaderCryptor().Create();
            var fileContentKeyBytes = ((V3.FileHeaderImpl)_fileHeader).GetContentKey().GetEncoded();
            _fileContentAesGcm = new AesGcm(fileContentKeyBytes);

            _cleartextChunkBuffer = new byte[CLEARTEXT_CHUNK_SIZE]; // Uses the constant
            // Ciphertext buffer size should also be based on the constant PAYLOAD_SIZE via CleartextChunkSize() or directly
            _ciphertextChunkBuffer = new Memory<byte>(new byte[_cryptor.FileContentCryptor().CiphertextChunkSize()]);
            
            // Initialize AAD buffer: 8 bytes for chunk number + header nonce length
            ReadOnlySpan<byte> headerNonce = ((V3.FileHeaderImpl)_fileHeader).GetNonce();
            _aadBuffer = new byte[8 + headerNonce.Length];
            headerNonce.CopyTo(_aadBuffer.AsSpan(8)); // Copy header nonce to the latter part of AAD buffer
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
#if DEBUG
            _metrics.StartTiming();
#endif
            _random.GetBytes(_perChunkNonce);
#if DEBUG
            _metrics.StopTiming(ref _metrics.TotalOperation1TimeMs); // NonceGen
            _metrics.StartTiming();
#endif
            BinaryPrimitives.WriteInt64BigEndian(_aadBuffer.AsSpan(0, 8), _currentChunkNumber);
#if DEBUG
            _metrics.StopTiming(ref _metrics.TotalOperation2TimeMs); // AADPrep
            _metrics.StartTiming();
#endif
            ((V3.FileContentCryptorImpl)_cryptor.FileContentCryptor()).EncryptChunk(
                _fileContentAesGcm,
                cleartextChunk,
                _ciphertextChunkBuffer, 
                _currentChunkNumber,
                _perChunkNonce, 
                _aadBuffer 
            );
#if DEBUG
            _metrics.StopTiming(ref _metrics.TotalOperation3TimeMs); // EncryptOp
#endif
            _currentChunkNumber++; 
            
            int actualEncryptedLength = V3.Constants.GCM_NONCE_SIZE + cleartextChunk.Length + V3.Constants.GCM_TAG_SIZE;
            
#if DEBUG
            _metrics.StartTiming();
#endif
            _outputStream.Write(_ciphertextChunkBuffer.Slice(0, actualEncryptedLength).Span);
#if DEBUG
            _metrics.StopTiming(ref _metrics.TotalOperation4TimeMs); // StreamWrite
            _metrics.IncrementChunksProcessed();
#endif
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
                        Flush();
                    }
                    finally
                    {
                        _fileContentAesGcm?.Dispose(); 
                        _fileHeader?.Dispose(); 

                        if (!_leaveOpen)
                        {
                            _outputStream?.Dispose();
                        }
                        _random?.Dispose(); 
#if DEBUG
                        _metrics?.Report();
#endif
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