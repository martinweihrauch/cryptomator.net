using CryptomatorLib.Api;
using CryptomatorLib.Common;
using System;
using System.IO;
using System.Threading.Tasks;

namespace CryptomatorLib.Tests.Common
{
    /// <summary>
    /// Simplified test version of DecryptingReadableByteChannel.
    /// Does not perform actual decryption, only logs.
    /// </summary>
    internal sealed class TestDecryptingReadableByteChannel : ISeekableByteChannel, IDisposable // Renamed class
    {
        private readonly ISeekableByteChannel _source;
        private readonly ICryptor _cryptor;
        private bool _closed;

        /// <summary>
        /// Simplified constructor for testing.
        /// </summary>
        /// <param name="source">The underlying channel to read (non-decrypted) data from.</param>
        /// <param name="cryptor">The cryptor (ignored in this test version).</param>
        public TestDecryptingReadableByteChannel(ISeekableByteChannel source, ICryptor cryptor) // Updated constructor name
        {
            _source = source ?? throw new ArgumentNullException(nameof(source));
            _cryptor = cryptor ?? throw new ArgumentNullException(nameof(cryptor));
            _closed = false;
            Console.WriteLine("Warning: Using simplified TestDecryptingReadableByteChannel (Test Version). No decryption will occur.");
        }

        public bool IsOpen => !_closed && _source.IsOpen;

        // Rename property to avoid conflict
        private long CurrentPositionProp
        {
            get => _source.Position;
            set => _source.Position = value;
        }

        // Implement Position() method required by interface
        public long Position()
        {
            return CurrentPositionProp;
        }

        // Implement Position(long) method required by interface (fluent)
        public ISeekableByteChannel Position(long newPosition)
        {
            CurrentPositionProp = newPosition;
            return this;
        }

        // Add CurrentPosition property required by interface
        public long CurrentPosition => Position();

        public long Size() => _source.Size();

        // Add CurrentSize property required by interface
        public long CurrentSize => Size();

        public async Task<int> Read(byte[] dst)
        {
            if (_closed)
            {
                throw new IOException("Channel closed");
            }
            Console.WriteLine($"Warning: Simplified Read requesting {dst.Length} bytes. Data not decrypted.");
            // In a real scenario, decryption would happen here after reading from source.
            // For the test version, we just read plain data from the source.
            var bytesRead = await _source.Read(dst);
            if (bytesRead == -1) // Check for end of stream
            {
                Close(); // Auto-close on EOF like some stream implementations
            }
            return bytesRead;
        }

        public int Read(byte[] buffer, int offset, int count)
        {
            if (_closed)
            {
                throw new IOException("Channel closed");
            }
            Console.WriteLine($"Warning: Simplified sync Read requesting {count} bytes. Data not decrypted.");
            // Simple synchronous read from source for the test version
            // Note: This assumes _source is a Stream or similar with a sync Read
            // Need to handle potential type issues if _source is strictly async channel
            if (_source is Stream sourceStream)
            {
                return sourceStream.Read(buffer, offset, count);
            }
            // Fallback or throw if not a stream? For now, throw.
            throw new NotSupportedException("Synchronous Read not directly supported by the underlying source type in this test stub.");
            // Alternatively, block on async version? (Generally discouraged)
            // var task = Read(buffer.AsMemory(offset, count));
            // return task.GetAwaiter().GetResult();
        }

        public int Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("Write operation is not supported by TestDecryptingReadableByteChannel.");
        }

        public long Seek(long offset) // Assuming Seek(long) signature from error
        {
            // Delegate seek to source if possible, otherwise throw
            // This assumes _source has a compatible Seek method.
            if (_source is Stream sourceStream)
            {
                // SeekOrigin.Begin is assumed; adjust if interface differs
                return sourceStream.Seek(offset, SeekOrigin.Begin);
            }
            throw new NotImplementedException("Seek not implemented in simplified test version or source doesn't support it.");
        }

        public void Close()
        {
            if (!_closed)
            {
                _closed = true;
                _source.Close();
                Console.WriteLine("Simplified TestDecryptingReadableByteChannel closed.");
            }
        }

        // Added Dispose method
        public void Dispose()
        {
            // Nothing specific to dispose in this simplified version, but implement the interface.
            Close();
        }

        public ISeekableByteChannel Truncate(long size)
        {
            // Simplification: delegate or throw?
            // throw new NotImplementedException("Truncate not supported in simplified test version.");
            // Or maybe just delegate?
            return _source.Truncate(size);
        }
    }
}