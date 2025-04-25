using System;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using CryptomatorLib.Api;

namespace CryptomatorLib.Tests.Benchmarks
{
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    public class EncryptionBenchmarks
    {
        private byte[] _sampleData;
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
        }

        [Benchmark]
        public byte[] AesGcmEncryption()
        {
            // Use the library's encryption method
            return AesGcmCryptor.Encrypt(_sampleData, _key, _iv);
        }

        [Benchmark]
        public byte[] AesCtrEncryption()
        {
            // Use the library's encryption method
            return AesCtrCryptor.Encrypt(_sampleData, _key, _iv);
        }
    }
}