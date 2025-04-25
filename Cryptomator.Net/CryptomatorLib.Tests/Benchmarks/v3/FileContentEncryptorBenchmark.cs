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
        private UVFMasterkey _masterkey;
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

            _masterkey = new UVFMasterkey(
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

            using (var outputChannel = new NullSeekableByteChannel())
            using (var encryptingChannel = new EncryptingWritableByteChannel(outputChannel, _cryptor))
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
        /// A seekable byte channel that discards all data written to it.
        /// </summary>
        private class NullSeekableByteChannel : ISeekableByteChannel
        {
            private bool _open = true;
            private long _position = 0;

            public bool IsOpen => _open;

            public long CurrentPosition
            {
                get
                {
                    if (!_open) throw new ObjectDisposedException(nameof(NullSeekableByteChannel));
                    return _position;
                }
            }

            public long CurrentSize
            {
                get
                {
                    if (!_open) throw new ObjectDisposedException(nameof(NullSeekableByteChannel));
                    return _position;
                }
            }

            public void Close()
            {
                _open = false;
            }

            public int Read(byte[] dst, int offset, int count)
            {
                throw new NotImplementedException("Read operation not supported in NullSeekableByteChannel");
            }

            public int Write(byte[] src, int offset, int count)
            {
                if (!_open) throw new ObjectDisposedException(nameof(NullSeekableByteChannel));
                _position += count;
                return count;
            }

            public long Seek(long position)
            {
                if (!_open) throw new ObjectDisposedException(nameof(NullSeekableByteChannel));
                _position = position;
                return _position;
            }

            public long Position()
            {
                if (!_open) throw new ObjectDisposedException(nameof(NullSeekableByteChannel));
                return _position;
            }

            public ISeekableByteChannel Position(long newPosition)
            {
                if (!_open) throw new ObjectDisposedException(nameof(NullSeekableByteChannel));
                _position = newPosition;
                return this;
            }

            public long Size()
            {
                if (!_open) throw new ObjectDisposedException(nameof(NullSeekableByteChannel));
                return _position;
            }

            public ISeekableByteChannel Truncate(long size)
            {
                if (!_open) throw new ObjectDisposedException(nameof(NullSeekableByteChannel));
                if (size < _position)
                {
                    _position = size;
                }
                return this;
            }

            public void Dispose()
            {
                Close();
            }
        }
    }
}