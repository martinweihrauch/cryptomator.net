using System;
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
    public class FileContentEncryptorBenchmark
    {
        private RandomNumberGenerator _csprng;
        private MockUVFMasterkey _masterkey;
        private CryptorImpl _cryptor;

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

            _masterkey = new MockUVFMasterkey(
                new System.Collections.Generic.Dictionary<int, byte[]> { { seedId, seed } },
                kdfSalt,
                seedId, // initialSeed
                seedId  // latestSeed
            );

            _cryptor = new CryptorImpl(_masterkey, _csprng);
        }

        [Benchmark]
        public void Benchmark1MegabyteEncryption()
        {
            EncryptData(1024 * 1024); // 1 MB
        }

        [Benchmark]
        public void Benchmark10MegabytesEncryption()
        {
            EncryptData(10 * 1024 * 1024); // 10 MB
        }

        [Benchmark(Description = "100MB Encryption (Long running)")]
        [BenchmarkCategory("LongRunning")]
        public void Benchmark100MegabytesEncryption()
        {
            EncryptData(100 * 1024 * 1024); // 100 MB
        }

        private void EncryptData(int sizeBytes)
        {
            // Create a buffer with the specified size
            byte[] buffer = new byte[1024 * 1024]; // Use 1MB chunks for writing
            new Random(42).NextBytes(buffer); // Fill with pseudo-random data

            // Create a dummy stream and wrap it in a test channel
            using var nullStream = new NullStream();
            using var channelAdapter = new NullTestChannel();

            using (var encryptingChannel = new CryptomatorLib.Tests.Common.TestEncryptingWritableByteChannel(channelAdapter, _cryptor))
            {
                int remaining = sizeBytes;
                while (remaining > 0)
                {
                    int chunkSize = Math.Min(buffer.Length, remaining);
                    encryptingChannel.Write(buffer, 0, chunkSize);
                    remaining -= chunkSize;
                }
            }
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            _csprng.Dispose();
        }

        /// <summary>
        /// A null stream that discards all data
        /// </summary>
        private class NullStream : Stream
        {
            private long _position = 0;

            public override bool CanRead => false;
            public override bool CanSeek => true;
            public override bool CanWrite => true;
            public override long Length => _position;

            public override long Position
            {
                get => _position;
                set => _position = value;
            }

            public override void Flush() { }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotImplementedException();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                switch (origin)
                {
                    case SeekOrigin.Begin:
                        _position = offset;
                        break;
                    case SeekOrigin.Current:
                        _position += offset;
                        break;
                    case SeekOrigin.End:
                        _position = Length + offset;
                        break;
                }
                return _position;
            }

            public override void SetLength(long value)
            {
                _position = value;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                _position += count;
            }
        }

        /// <summary>
        /// A test channel that implements ISeekableByteChannel and discards all data
        /// </summary>
        private class NullTestChannel : IWritableByteChannel, IDisposable
        {
            private bool _open = true;

            public bool IsOpen => _open;

            public void Close() => _open = false;

            public void Dispose() => Close();

            public Task<int> Write(byte[] src)
            {
                return Task.FromResult(src.Length);
            }
        }
    }
}