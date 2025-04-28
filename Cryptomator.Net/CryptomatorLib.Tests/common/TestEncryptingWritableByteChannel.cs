using System;
using System.IO;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace CryptomatorLib.Tests.Common
{
    /// <summary>
    /// Simplified test version of EncryptingWritableByteChannel.
    /// Does not perform actual encryption, only logs.
    /// </summary>
    internal class TestEncryptingWritableByteChannel : IWritableByteChannel, IDisposable // Renamed class
    {
        private readonly IWritableByteChannel _sink;
        private readonly ICryptor _cryptor;
        private bool _closed;

        /// <summary>
        /// Simplified constructor for testing.
        /// </summary>
        /// <param name="sink">The underlying channel to write (non-encrypted) data to.</param>
        /// <param name="cryptor">The cryptor (ignored in this test version).</param>
        public TestEncryptingWritableByteChannel(IWritableByteChannel sink, ICryptor cryptor) // Updated constructor name
        {
            _sink = sink ?? throw new ArgumentNullException(nameof(sink));
            _cryptor = cryptor ?? throw new ArgumentNullException(nameof(cryptor)); // Still requires ICryptor
            _closed = false;
            Console.WriteLine("Warning: Using simplified TestEncryptingWritableByteChannel (Test Version). No encryption will occur.");
        }

        public bool IsOpen => !_closed;

        public async Task<int> Write(byte[] src)
        {
            if (_closed)
            {
                throw new IOException("Channel closed");
            }
            Console.WriteLine($"Warning: Simplified Write called with {src.Length} bytes. Data not encrypted.");
            // In a real scenario, encryption would happen here.
            // For the test version, we just return the count as if write succeeded.
            // Optionally, write plain data to sink for verification?
            // await _sink.Write(src); 
            return src.Length;
        }

        public void Close()
        {
            if (!_closed)
            {
                _closed = true;
                _sink.Close();
                Console.WriteLine("Simplified TestEncryptingWritableByteChannel closed.");
            }
        }

        // Added Dispose method
        public void Dispose()
        {
            // Nothing specific to dispose in this simplified version, but implement the interface.
            Close();
        }

        // Other methods from ISeekableByteChannel could be added here if needed
        // throwing NotImplementedException, e.g.:
        // public long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        // public long Size() => throw new NotImplementedException();
        // public ISeekableByteChannel Truncate(long size) => throw new NotImplementedException();
    }
}