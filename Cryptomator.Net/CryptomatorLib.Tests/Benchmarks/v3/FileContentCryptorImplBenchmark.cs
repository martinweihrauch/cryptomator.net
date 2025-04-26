using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using CryptomatorLib.Api;
using CryptomatorLib.Common;
using CommonConstants = CryptomatorLib.Common.Constants;
using CryptomatorLib.Tests.Common;
using CryptomatorLib.V3;

namespace CryptomatorLib.Tests.Benchmarks.v3
{
    // Mock implementation of RevolvingMasterkey for testing
    public class MockRevolvingMasterkey : RevolvingMasterkey
    {
        private readonly UVFMasterkey _masterkey;
        
        public MockRevolvingMasterkey(UVFMasterkey masterkey)
        {
            _masterkey = masterkey;
        }
        
        public DestroyableMasterkey Current() => _masterkey.Current();
        
        public DestroyableMasterkey GetBySeedId(string seedId) => _masterkey.GetBySeedId(seedId);
        
        public int GetCurrentRevision() => _masterkey.GetCurrentRevision();
        
        public int GetInitialRevision() => _masterkey.GetInitialRevision();
        
        public int GetFirstRevision() => _masterkey.GetFirstRevision();
        
        public byte[] GetRootDirId() => _masterkey.GetRootDirId();
        
        public bool HasRevision(int revision) => _masterkey.HasRevision(revision);
        
        public DestroyableSecretKey SubKey(int seedId, int size, byte[] context, string algorithm) 
            => _masterkey.SubKey(seedId, size, context, algorithm);
        
        public byte[] GetRaw() => _masterkey.GetRaw();
        
        public void Destroy() => _masterkey.Destroy();
        
        public bool IsDestroyed() => _masterkey.IsDestroyed();
        
        public void Dispose() => _masterkey.Dispose();
    }
    
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [RankColumn]
    public class FileContentCryptorImplBenchmark
    {
        private readonly RandomNumberGenerator _randomMock;
        private readonly DestroyableSecretKey _encKey;
        private readonly byte[] _headerNonce;
        private readonly ReadOnlyMemory<byte> _cleartextChunk;
        private readonly Memory<byte> _ciphertextChunk;
        private readonly Memory<byte> _decryptedChunk;
        private readonly FileContentCryptorImpl _fileContentCryptor;
        private readonly FileHeader _header;
        private long _chunkNumber;

        public FileContentCryptorImplBenchmark()
        {
            // Initialize with fixed seed for consistent benchmarks
            _randomMock = RandomNumberGenerator.Create();
            
            // Create a mock revolving masterkey
            var masterkey = new MockUVFMasterkey(
                new System.Collections.Generic.Dictionary<int, byte[]> { { 1, new byte[32] } },
                new byte[32],
                1,
                1
            );
            var revolvingMasterkey = new MockRevolvingMasterkey(masterkey);
            
            _encKey = new DestroyableSecretKey(new byte[16], "AES");
            _headerNonce = new byte[FileHeaderImpl.NONCE_LEN];
            
            // Create file header for testing
            _header = new FileHeaderImpl(1, _headerNonce, _encKey);
            
            _cleartextChunk = new Memory<byte>(new byte[CommonConstants.PAYLOAD_SIZE]);
            _ciphertextChunk = new Memory<byte>(new byte[CommonConstants.CHUNK_SIZE]);
            _decryptedChunk = new Memory<byte>(new byte[CommonConstants.PAYLOAD_SIZE]);
            
            _fileContentCryptor = new FileContentCryptorImpl(revolvingMasterkey, _randomMock);

            // Initial setup - encrypt a chunk for decryption tests
            _fileContentCryptor.EncryptChunk(_cleartextChunk, _ciphertextChunk, 0L, _header);
        }

        [IterationSetup]
        public void IterationSetup()
        {
            _chunkNumber = new Random().Next();
            _randomMock.GetBytes(_headerNonce);
        }

        [Benchmark]
        public void BenchmarkEncryption()
        {
            _fileContentCryptor.EncryptChunk(_cleartextChunk, _ciphertextChunk, _chunkNumber, _header);
        }

        [Benchmark]
        public void BenchmarkDecryption()
        {
            _fileContentCryptor.DecryptChunk(_ciphertextChunk, _decryptedChunk, 0L, _header, true);
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            _encKey.Dispose();
            _randomMock.Dispose();
        }
    }
}