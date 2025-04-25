using System;
using System.IO;
using CryptomatorLib.Common;

namespace CryptomatorLib.Tests.Common
{
    /// <summary>
    /// A mock implementation of ISeekableByteChannel for testing purposes.
    /// </summary>
    public class SeekableByteChannelMock : ISeekableByteChannel
    {
        private bool _open = true;
        private readonly MemoryStream _buffer;

        /// <summary>
        /// Creates a new SeekableByteChannelMock with the given buffer.
        /// </summary>
        /// <param name="buffer">The underlying buffer to use</param>
        public SeekableByteChannelMock(MemoryStream buffer)
        {
            _buffer = buffer ?? throw new ArgumentNullException(nameof(buffer));
        }

        /// <summary>
        /// Creates a new SeekableByteChannelMock with a new buffer of the given size.
        /// </summary>
        /// <param name="size">The size of the buffer in bytes</param>
        public SeekableByteChannelMock(int size)
        {
            _buffer = new MemoryStream(size);
        }

        /// <inheritdoc />
        public bool IsOpen => _open;

        public long CurrentPosition
        {
            get
            {
                EnsureOpen();
                return _buffer.Position;
            }
        }

        public long CurrentSize
        {
            get
            {
                EnsureOpen();
                return _buffer.Length;
            }
        }

        /// <inheritdoc />
        public void Close()
        {
            _open = false;
            _buffer.Close();
        }

        /// <inheritdoc />
        public int Read(byte[] dst, int offset, int count)
        {
            EnsureOpen();

            if (!HasRemaining())
            {
                return -1;
            }

            int num = (int)Math.Min(_buffer.Length - _buffer.Position, count);
            int bytesRead = _buffer.Read(dst, offset, num);
            return bytesRead;
        }

        /// <inheritdoc />
        public int Write(byte[] src, int offset, int count)
        {
            EnsureOpen();

            int num = (int)Math.Min(_buffer.Length - _buffer.Position, count);
            _buffer.Write(src, offset, num);
            return num;
        }

        /// <inheritdoc />
        public long Seek(long position)
        {
            EnsureOpen();
            return _buffer.Seek(position, SeekOrigin.Begin);
        }

        /// <inheritdoc />
        public long Position()
        {
            EnsureOpen();
            return _buffer.Position;
        }

        /// <inheritdoc />
        public ISeekableByteChannel Position(long newPosition)
        {
            EnsureOpen();

            _buffer.Position = newPosition;
            return this;
        }

        /// <inheritdoc />
        public long Size()
        {
            EnsureOpen();
            return _buffer.Length;
        }

        /// <inheritdoc />
        public ISeekableByteChannel Truncate(long size)
        {
            EnsureOpen();

            if (size < _buffer.Position)
            {
                _buffer.Position = size;
            }

            _buffer.SetLength(size);
            return this;
        }

        private bool HasRemaining()
        {
            return _buffer.Position < _buffer.Length;
        }

        private void EnsureOpen()
        {
            if (!_open)
            {
                throw new IOException("Channel is closed");
            }
        }

        /// <inheritdoc />
        public void Dispose()
        {
            Close();
        }
    }
}