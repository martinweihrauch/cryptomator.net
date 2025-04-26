using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using CryptomatorLib.Api;
using CryptomatorLib.Common;

namespace CryptomatorLib.Tests.Benchmarks
{
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    public class DecryptionBenchmarks
    {
        private byte[] _sampleData;
        private byte[] _encryptedDataGcm;
        private byte[] _encryptedDataCtr;
        private byte[] _key;
        private byte[] _iv;

        [GlobalSetup]
        public void Setup()
        {
            // Create sample data (1MB)
            _sampleData = new byte[1024 * 1024];
            new Random(42).NextBytes(_sampleData);

            // Create encryption key and IV
            _key = new byte[32]; // 256-bit key
            _iv = new byte[16];  // 128-bit IV
            new Random(123).NextBytes(_key);
            new Random(456).NextBytes(_iv);

            // Pre-encrypt data for decryption benchmarks
            _encryptedDataGcm = AesGcmCryptor.Encrypt(_sampleData, _key, _iv);
            _encryptedDataCtr = AesCtrCryptor.Encrypt(_sampleData, _key, _iv);
        }

        [Benchmark]
        public byte[] AesGcmDecryption()
        {
            return AesGcmCryptor.Decrypt(_encryptedDataGcm, _key, _iv);
        }

        [Benchmark]
        public byte[] AesCtrDecryption()
        {
            return AesCtrCryptor.Decrypt(_encryptedDataCtr, _key, _iv);
        }
    }
}