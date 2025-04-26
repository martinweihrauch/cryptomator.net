using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;
using CryptomatorLib.Common;
using CryptomatorLib.IO; // Benchmark-specific streams
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace CryptomatorLib.Tests.Benchmarks
{
    [MemoryDiagnoser]
    public class StreamBenchmarks
    {
        private byte[] _testData;
        private byte[] _key;
        private byte[] _iv;
        private MemoryStream _inputStream;
        private MemoryStream _outputStream;

        [Params(4096, 1024 * 1024, 10 * 1024 * 1024)]
        public int DataSize { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            // Create test data
            _testData = new byte[DataSize];
            new Random(42).NextBytes(_testData);

            // Create encryption key and IV
            _key = new byte[32]; // 256-bit key
            _iv = new byte[16]; // 128-bit IV
            new Random(42).NextBytes(_key);
            new Random(43).NextBytes(_iv);

            // Prepare streams
            _inputStream = new MemoryStream(_testData);
            _outputStream = new MemoryStream();
        }

        [Benchmark]
        public async Task EncryptingStream_Write()
        {
            _inputStream.Position = 0;
            _outputStream.Position = 0;
            _outputStream.SetLength(0);

            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;

            using var encryptingStream = new AesCtrEncryptingStream(_outputStream, aes);
            await _inputStream.CopyToAsync(encryptingStream);
            await encryptingStream.FlushAsync();
        }

        [Benchmark]
        public async Task EncryptingStream_Read()
        {
            _inputStream.Position = 0;
            _outputStream.Position = 0;
            _outputStream.SetLength(0);

            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;

            using var encryptingStream = new AesCtrEncryptingStream(_inputStream, aes);
            await encryptingStream.CopyToAsync(_outputStream);
        }

        [Benchmark]
        public async Task DecryptingStream_Read()
        {
            // First encrypt the data
            _inputStream.Position = 0;
            _outputStream.Position = 0;
            _outputStream.SetLength(0);

            using var aesEncrypt = Aes.Create();
            aesEncrypt.Key = _key;
            aesEncrypt.IV = _iv;

            using (var encryptingStream = new AesCtrEncryptingStream(_outputStream, aesEncrypt))
            {
                await _inputStream.CopyToAsync(encryptingStream);
                await encryptingStream.FlushAsync();
            }

            // Then decrypt it
            var encryptedData = _outputStream.ToArray();
            var encryptedStream = new MemoryStream(encryptedData);
            var decryptedStream = new MemoryStream();

            using var aesDecrypt = Aes.Create();
            aesDecrypt.Key = _key;
            aesDecrypt.IV = _iv;

            using var decryptingStream = new AesCtrDecryptingStream(encryptedStream, aesDecrypt);
            await decryptingStream.CopyToAsync(decryptedStream);
        }

        [Benchmark]
        public async Task AesTransform_DirectCryptor()
        {
            _inputStream.Position = 0;
            _outputStream.Position = 0;
            _outputStream.SetLength(0);

            // Use the library's built-in AesCtrCryptor directly
            byte[] encrypted = AesCtrCryptor.Encrypt(_testData, _key, _iv);
            await _outputStream.WriteAsync(encrypted, 0, encrypted.Length);
        }

#if BENCHMARKS
        public static void Main(string[] args)
        {
            var summary = BenchmarkDotNet.Running.BenchmarkRunner.Run<StreamBenchmarks>();
        }
#endif
    }
} 