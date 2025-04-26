using System;
using System.IO;
using CryptomatorLib.Api;
using CryptomatorLib.Common;

namespace CryptomatorLib.Tests.Common
{
    /// <summary>
    /// A readable byte channel that decrypts data from an underlying channel.
    /// </summary>
    public class DecryptingReadableByteChannel : ISeekableByteChannel, IDisposable
    {
        private readonly ISeekableByteChannel _channel;
        private readonly Cryptor _cryptor;
        private readonly bool _authenticate;
        private readonly byte[] _buffer;
        private readonly byte[] _decryptedBuffer;
        private int _bufferPosition = 0;
        private int _bufferFilled = 0;
        private long _position = 0;
        private long _headerSize;
        private long _chunksRead = 0;
        private bool _headerRead = false;
        private bool _endOfStream = false;
        private bool _closed = false;
        private FileHeader? _header = null;
        
        /// <summary>
        /// Creates a new decrypting readable byte channel.
        /// </summary>
        /// <param name="channel">The underlying channel to read from</param>
        /// <param name="cryptor">The cryptor to use for decryption</param>
        /// <param name="authenticate">Whether to authenticate the data</param>
        public DecryptingReadableByteChannel(ISeekableByteChannel channel, Cryptor cryptor, bool authenticate = true)
        {
            _channel = channel ?? throw new ArgumentNullException(nameof(channel));
            _cryptor = cryptor ?? throw new ArgumentNullException(nameof(cryptor));
            _authenticate = authenticate;
            
            _headerSize = _cryptor.FileHeaderCryptor().HeaderSize();
            int ciphertextChunkSize = _cryptor.FileContentCryptor().CiphertextChunkSize();
            int cleartextChunkSize = _cryptor.FileContentCryptor().CleartextChunkSize();
            
            _buffer = new byte[ciphertextChunkSize];
            _decryptedBuffer = new byte[cleartextChunkSize];
            
            _bufferPosition = 0;
            _bufferFilled = 0;
            _position = 0;
            _chunksRead = 0;
            _headerRead = false;
            _endOfStream = false;
            _closed = false;
        }
        
        /// <summary>
        /// Gets the current position of the channel.
        /// </summary>
        public long CurrentPosition => _position;
        
        /// <summary>
        /// Gets the current size of the channel.
        /// </summary>
        public long CurrentSize => throw new NotSupportedException("Decrypting channel size cannot be determined");
        
        /// <summary>
        /// Closes the channel.
        /// </summary>
        public void Close()
        {
            if (!_closed)
            {
                _channel.Close();
                _closed = true;
            }
        }
        
        /// <summary>
        /// Reads bytes from the channel.
        /// </summary>
        /// <param name="buffer">The buffer to read into</param>
        /// <param name="offset">The offset in the buffer to start writing data to</param>
        /// <param name="count">The maximum number of bytes to read</param>
        /// <returns>The number of bytes read</returns>
        public int Read(byte[] buffer, int offset, int count)
        {
            if (_closed)
            {
                throw new ObjectDisposedException(nameof(DecryptingReadableByteChannel));
            }
            
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }
            
            if (offset < 0 || count < 0 || offset + count > buffer.Length)
            {
                throw new ArgumentOutOfRangeException();
            }
            
            if (_endOfStream)
            {
                return 0;
            }
            
            // Read header if not done yet
            if (!_headerRead)
            {
                ReadHeader();
            }
            
            int totalRead = 0;
            while (totalRead < count && !_endOfStream)
            {
                // If buffer is empty, fill it
                if (_bufferPosition >= _bufferFilled)
                {
                    FillBuffer();
                    
                    // If still empty after filling, we've reached the end
                    if (_bufferPosition >= _bufferFilled)
                    {
                        _endOfStream = true;
                        break;
                    }
                }
                
                // Copy data from buffer to output
                int toCopy = Math.Min(count - totalRead, _bufferFilled - _bufferPosition);
                Buffer.BlockCopy(_decryptedBuffer, _bufferPosition, buffer, offset + totalRead, toCopy);
                
                _bufferPosition += toCopy;
                _position += toCopy;
                totalRead += toCopy;
            }
            
            return totalRead;
        }
        
        /// <summary>
        /// Writes bytes to the channel. Not supported for readable channel.
        /// </summary>
        public int Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("This channel is read-only");
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
                throw new ObjectDisposedException(nameof(DecryptingReadableByteChannel));
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
            throw new NotSupportedException("Decrypting channel size cannot be determined");
        }
        
        /// <summary>
        /// Disposes the channel.
        /// </summary>
        public void Dispose()
        {
            Close();
            GC.SuppressFinalize(this);
        }
        
        private void ReadHeader()
        {
            byte[] headerBytes = new byte[(int)_headerSize];
            int bytesRead = _channel.Read(headerBytes, 0, headerBytes.Length);
            
            if (bytesRead < headerBytes.Length)
            {
                throw new IOException("Incomplete file header");
            }
            
            ReadOnlyMemory<byte> headerMemory = new ReadOnlyMemory<byte>(headerBytes);
            _header = _cryptor.FileHeaderCryptor().DecryptHeader(headerMemory);
            _headerRead = true;
        }
        
        private void FillBuffer()
        {
            // Reset buffer position
            _bufferPosition = 0;
            _bufferFilled = 0;
            
            // Read from the underlying channel
            int bytesRead = _channel.Read(_buffer, 0, _buffer.Length);
            
            if (bytesRead == 0)
            {
                // End of stream
                return;
            }
            
            try
            {
                // Decrypt the chunk
                if (_header == null)
                {
                    throw new InvalidOperationException("Header not initialized");
                }
                
                ReadOnlyMemory<byte> ciphertext = new ReadOnlyMemory<byte>(_buffer, 0, bytesRead);
                var cleartext = _cryptor.FileContentCryptor().DecryptChunk(ciphertext, _chunksRead, _header, _authenticate);
                
                // Copy to decrypted buffer
                cleartext.CopyTo(_decryptedBuffer);
                
                // Set the buffer filled size based on the actual cleartext size
                _bufferFilled = cleartext.Length;
                
                // Increment chunks read
                _chunksRead++;
            }
            catch (Exception ex)
            {
                throw new IOException("Failed to decrypt chunk", ex);
            }
        }
    }
} 