using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using CryptomatorLib.Tests.Common;
using CryptomatorLib.V3;

namespace CryptomatorLib.Tests.Benchmarks.v3
{
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [RankColumn]
    public class FileContentDecryptorBenchmark
    {
        private const int OneMB = 1024 * 1024;

        private RandomNumberGenerator _csprng;
        private UVFMasterkey _masterkey;
        private CryptorImpl _cryptor;
        private byte[] _encryptedData1MB;
        private byte[] _encryptedData10MB;

        [GlobalSetup]
        public void Setup()
        {
            _csprng = RandomNumberGenerator.Create();

            // Create a basic masterkey for testing
            byte[] seed = new byte[32];
            _csprng.GetBytes(seed);

            byte[] kdfSalt = new byte[32];
            _csprng.GetBytes(kdfSalt);

            int seedId = 12345; // Arbitrary seed ID

            _masterkey = new UVFMasterkey(
                new Dictionary<int, byte[]> { { seedId, seed } },
                kdfSalt,
                seedId, // initialSeed
                seedId  // latestSeed
            );

            _cryptor = new CryptorImpl(_masterkey, _csprng);

            // Pre-generate encrypted data for decryption benchmarks
            _encryptedData1MB = GenerateEncryptedData(OneMB);
            _encryptedData10MB = GenerateEncryptedData(10 * OneMB);
        }

        private byte[] GenerateEncryptedData(int sizeBytes)
        {
            byte[] clearData = new byte[sizeBytes];
            new Random(42).NextBytes(clearData);

            using (var outputStream = new MemoryStream())
            {
                using (var outputChannel = new StreamAsSeekableByteChannel(outputStream))
                using (var encryptingChannel = new EncryptingWritableByteChannel(outputChannel, _cryptor))
                {
                    encryptingChannel.Write(clearData, 0, clearData.Length);
                }

                return outputStream.ToArray();
            }
        }

        [Benchmark]
        public void Benchmark1MegabyteDecryption()
        {
            DecryptData(_encryptedData1MB);
        }

        [Benchmark]
        public void Benchmark10MegabytesDecryption()
        {
            DecryptData(_encryptedData10MB);
        }

        private void DecryptData(byte[] encryptedData)
        {
            using (var inputStream = new MemoryStream(encryptedData))
            using (var inputChannel = new StreamAsSeekableByteChannel(inputStream))
            using (var decryptingChannel = new DecryptingReadableByteChannel(inputChannel, _cryptor))
            using (var outputStream = new NullOutputStream())
            {
                byte[] buffer = new byte[64 * 1024]; // 64KB buffer for reading
                int bytesRead;

                while ((bytesRead = decryptingChannel.Read(buffer, 0, buffer.Length)) > 0)
                {
                    outputStream.Write(buffer, 0, bytesRead);
                }
            }
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            _csprng.Dispose();
        }

        /// <summary>
        /// Stream implementation that discards all data written to it
        /// </summary>
        private class NullOutputStream : Stream
        {
            public override bool CanRead => false;
            public override bool CanSeek => false;
            public override bool CanWrite => true;

            public override long Length => throw new NotImplementedException();

            public override long Position
            {
                get => throw new NotImplementedException();
                set => throw new NotImplementedException();
            }

            public override void Flush() { }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotImplementedException();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotImplementedException();
            }

            public override void SetLength(long value)
            {
                throw new NotImplementedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                // Do nothing - discard the data
            }
        }

        /// <summary>
        /// Adapter that converts a Stream to an ISeekableByteChannel
        /// </summary>
        private class StreamAsSeekableByteChannel : ISeekableByteChannel
        {
            private readonly Stream _stream;
            private bool _closed = false;

            public StreamAsSeekableByteChannel(Stream stream)
            {
                _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            }

            public bool IsOpen => !_closed && _stream.CanRead;

            public long CurrentPosition
            {
                get
                {
                    if (_closed) throw new ObjectDisposedException(nameof(StreamAsSeekableByteChannel));
                    return _stream.Position;
                }
            }

            public long CurrentSize
            {
                get
                {
                    if (_closed) throw new ObjectDisposedException(nameof(StreamAsSeekableByteChannel));
                    return _stream.Length;
                }
            }

            public void Close()
            {
                if (!_closed)
                {
                    _stream.Close();
                    _closed = true;
                }
            }

            public void Dispose()
            {
                Close();
            }

            public int Read(byte[] dst, int offset, int count)
            {
                if (_closed) throw new ObjectDisposedException(nameof(StreamAsSeekableByteChannel));
                return _stream.Read(dst, offset, count);
            }

            public int Write(byte[] src, int offset, int count)
            {
                if (_closed) throw new ObjectDisposedException(nameof(StreamAsSeekableByteChannel));
                _stream.Write(src, offset, count);
                return count;
            }

            public long Seek(long position)
            {
                if (_closed) throw new ObjectDisposedException(nameof(StreamAsSeekableByteChannel));
                return _stream.Seek(position, SeekOrigin.Begin);
            }

            public long Position()
            {
                if (_closed) throw new ObjectDisposedException(nameof(StreamAsSeekableByteChannel));
                return _stream.Position;
            }

            public ISeekableByteChannel Position(long newPosition)
            {
                if (_closed) throw new ObjectDisposedException(nameof(StreamAsSeekableByteChannel));
                _stream.Position = newPosition;
                return this;
            }

            public long Size()
            {
                if (_closed) throw new ObjectDisposedException(nameof(StreamAsSeekableByteChannel));
                return _stream.Length;
            }

            public ISeekableByteChannel Truncate(long size)
            {
                if (_closed) throw new ObjectDisposedException(nameof(StreamAsSeekableByteChannel));
                _stream.SetLength(size);
                return this;
            }
        }
    }
}