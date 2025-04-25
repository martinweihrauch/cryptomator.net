using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using CryptomatorLib.V3;

namespace CryptomatorLib.Tests.Benchmarks.v3
{
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [RankColumn]
    public class FileContentCryptorImplBenchmark
    {
        private readonly RandomNumberGenerator _randomMock;
        private readonly DestroyableSecretKey _encKey;
        private readonly byte[] _headerNonce;
        private readonly byte[] _cleartextChunk;
        private readonly byte[] _ciphertextChunk;
        private readonly FileContentCryptorImpl _fileContentCryptor;
        private long _chunkNumber;

        public FileContentCryptorImplBenchmark()
        {
            // Initialize with fixed seed for consistent benchmarks
            _randomMock = RandomNumberGenerator.Create();
            _encKey = new DestroyableSecretKey(new byte[16], "AES");
            _headerNonce = new byte[FileHeaderImpl.NONCE_LEN];
            _cleartextChunk = new byte[Constants.PAYLOAD_SIZE];
            _ciphertextChunk = new byte[Constants.CHUNK_SIZE];
            _fileContentCryptor = new FileContentCryptorImpl(_randomMock);

            // Initial setup - encrypt a chunk for decryption tests
            _fileContentCryptor.EncryptChunk(_cleartextChunk, 0, _cleartextChunk.Length,
                _ciphertextChunk, 0, 0L, new byte[12], _encKey);
        }

        [IterationSetup]
        public void IterationSetup()
        {
            _chunkNumber = new Random().Next();
            _randomMock.GetBytes(_headerNonce);
            _randomMock.GetBytes(_cleartextChunk);
        }

        [Benchmark]
        public void BenchmarkEncryption()
        {
            _fileContentCryptor.EncryptChunk(_cleartextChunk, 0, _cleartextChunk.Length,
                _ciphertextChunk, 0, _chunkNumber, _headerNonce, _encKey);
        }

        [Benchmark]
        public void BenchmarkDecryption()
        {
            _fileContentCryptor.DecryptChunk(_ciphertextChunk, 0, _ciphertextChunk.Length,
                _cleartextChunk, 0, 0L, new byte[12], _encKey);
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            _encKey.Dispose();
            _randomMock.Dispose();
        }
    }
}