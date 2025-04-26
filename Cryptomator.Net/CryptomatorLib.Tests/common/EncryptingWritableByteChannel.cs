using System;
using System.IO;
using CryptomatorLib.Api;
using CryptomatorLib.Common;

namespace CryptomatorLib.Tests.Common
{
    /// <summary>
    /// A writable byte channel that encrypts data before writing to an underlying channel.
    /// </summary>
    public class EncryptingWritableByteChannel : ISeekableByteChannel, IDisposable
    {
        private readonly ISeekableByteChannel _channel;
        private readonly Cryptor _cryptor;
        private readonly FileHeader _header;
        private readonly byte[] _buffer;
        private readonly byte[] _encryptedBuffer;
        private int _bufferPosition = 0;
        private long _position = 0;
        private bool _headerWritten = false;
        private bool _closed = false;
        
        /// <summary>
        /// Creates a new encrypting writable byte channel.
        /// </summary>
        /// <param name="channel">The underlying channel to write to</param>
        /// <param name="cryptor">The cryptor to use for encryption</param>
        public EncryptingWritableByteChannel(ISeekableByteChannel channel, Cryptor cryptor)
        {
            _channel = channel ?? throw new ArgumentNullException(nameof(channel));
            _cryptor = cryptor ?? throw new ArgumentNullException(nameof(cryptor));
            
            _header = _cryptor.FileHeaderCryptor().Create();
            
            int cleartextChunkSize = _cryptor.FileContentCryptor().CleartextChunkSize();
            int ciphertextChunkSize = _cryptor.FileContentCryptor().CiphertextChunkSize();
            
            _buffer = new byte[cleartextChunkSize];
            _encryptedBuffer = new byte[ciphertextChunkSize];
            
            _bufferPosition = 0;
            _position = 0;
            _headerWritten = false;
            _closed = false;
        }
        
        /// <summary>
        /// Gets the current position of the channel.
        /// </summary>
        public long CurrentPosition => _position;
        
        /// <summary>
        /// Gets the current size of the channel.
        /// </summary>
        public long CurrentSize => _position;
        
        /// <summary>
        /// Closes the channel.
        /// </summary>
        public void Close()
        {
            if (!_closed)
            {
                // Flush any remaining data
                Flush();
                
                // Close the underlying channel
                _channel.Close();
                _closed = true;
            }
        }
        
        /// <summary>
        /// Reads bytes from the channel. Not supported for writable channel.
        /// </summary>
        public int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("This channel is write-only");
        }
        
        /// <summary>
        /// Writes bytes to the channel.
        /// </summary>
        /// <param name="buffer">The buffer to write from</param>
        /// <param name="offset">The offset in the buffer to start reading data from</param>
        /// <param name="count">The number of bytes to write</param>
        /// <returns>The number of bytes written</returns>
        public int Write(byte[] buffer, int offset, int count)
        {
            if (_closed)
            {
                throw new ObjectDisposedException(nameof(EncryptingWritableByteChannel));
            }
            
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }
            
            if (offset < 0 || count < 0 || offset + count > buffer.Length)
            {
                throw new ArgumentOutOfRangeException();
            }
            
            // Write the header if not done yet
            if (!_headerWritten)
            {
                WriteHeader();
            }
            
            int remaining = count;
            while (remaining > 0)
            {
                int toCopy = Math.Min(remaining, _buffer.Length - _bufferPosition);
                Buffer.BlockCopy(buffer, offset + (count - remaining), _buffer, _bufferPosition, toCopy);
                
                _bufferPosition += toCopy;
                _position += toCopy;
                remaining -= toCopy;
                
                if (_bufferPosition == _buffer.Length)
                {
                    FlushBuffer();
                }
            }
            
            return count;
        }
        
        /// <summary>
        /// Flushes the buffer to the underlying channel.
        /// </summary>
        public void Flush()
        {
            if (_closed)
            {
                throw new ObjectDisposedException(nameof(EncryptingWritableByteChannel));
            }
            
            if (_bufferPosition > 0)
            {
                FlushBuffer();
            }
        }
        
        /// <summary>
        /// Seeks to a position in the channel.
        /// </summary>
        public long Seek(long position)
        {
            throw new NotSupportedException("This channel does not support seeking");
        }
        
        /// <summary>
        /// Gets the current position of the channel.
        /// </summary>
        public long Position()
        {
            if (_closed)
            {
                throw new ObjectDisposedException(nameof(EncryptingWritableByteChannel));
            }
            
            return _position;
        }
        
        /// <summary>
        /// Sets the channel's position.
        /// </summary>
        public ISeekableByteChannel Position(long newPosition)
        {
            throw new NotSupportedException("This channel does not support repositioning");
        }
        
        /// <summary>
        /// Gets the size of the channel.
        /// </summary>
        public long Size()
        {
            if (_closed)
            {
                throw new ObjectDisposedException(nameof(EncryptingWritableByteChannel));
            }
            
            return _position;
        }
        
        /// <summary>
        /// Disposes the channel.
        /// </summary>
        public void Dispose()
        {
            Close();
            GC.SuppressFinalize(this);
        }
        
        private void WriteHeader()
        {
            var headerBytes = _cryptor.FileHeaderCryptor().EncryptHeader(_header);
            byte[] headerArray = headerBytes.ToArray();
            _channel.Write(headerArray, 0, headerArray.Length);
            _headerWritten = true;
        }
        
        private void FlushBuffer()
        {
            if (_bufferPosition > 0)
            {
                // Calculate chunk number based on position
                long chunkNumber = (_position - _bufferPosition) / _buffer.Length;
                
                // If buffer is not full, zero the remainder
                if (_bufferPosition < _buffer.Length)
                {
                    Array.Clear(_buffer, _bufferPosition, _buffer.Length - _bufferPosition);
                }
                
                // Encrypt the buffer
                ReadOnlyMemory<byte> cleartext = new ReadOnlyMemory<byte>(_buffer, 0, _bufferPosition);
                var ciphertext = _cryptor.FileContentCryptor().EncryptChunk(cleartext, chunkNumber, _header);
                
                // Write the encrypted data
                byte[] encryptedData = ciphertext.ToArray();
                _channel.Write(encryptedData, 0, encryptedData.Length);
                
                // Reset the buffer position
                _bufferPosition = 0;
            }
        }
    }
} 