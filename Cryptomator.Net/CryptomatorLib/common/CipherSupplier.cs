using System;
using System.Security.Cryptography;

namespace CryptomatorLib.Common
{
    /// <summary>
    /// Supplier for cryptographic ciphers.
    /// </summary>
    public sealed class CipherSupplier
    {
        /// <summary>
        /// AES in CTR mode
        /// </summary>
        public static readonly CipherSupplier AES_CTR = new CipherSupplier("AES-CTR");

        /// <summary>
        /// AES in GCM mode
        /// </summary>
        public static readonly CipherSupplier AES_GCM = new CipherSupplier("AES-GCM");

        /// <summary>
        /// AES Key Wrap (RFC 3394)
        /// </summary>  
        public static readonly CipherSupplier RFC3394_KEYWRAP = new CipherSupplier("AES-WRAP");

        private readonly string _algorithm;
        private readonly ObjectPool<ICryptoTransform> _encryptorPool;
        private readonly ObjectPool<ICryptoTransform> _decryptorPool;

        /// <summary>
        /// Creates a new cipher supplier.
        /// </summary>
        /// <param name="algorithm">The encryption algorithm name</param>
        public CipherSupplier(string algorithm)
        {
            _algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            _encryptorPool = new ObjectPool<ICryptoTransform>(() => null); // Initialized lazily
            _decryptorPool = new ObjectPool<ICryptoTransform>(() => null); // Initialized lazily
        }

        /// <summary>
        /// Leases a reusable cipher object initialized for encryption.
        /// </summary>
        /// <param name="key">Encryption key</param>
        /// <param name="iv">IV/Nonce</param>
        /// <returns>A lease supplying a crypto transform for encryption</returns>
        public ObjectPool<ICryptoTransform>.Lease<ICryptoTransform> EncryptionCipher(DestroyableSecretKey key, byte[] iv)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            
            return EncryptionCipher(key.GetRaw(), iv);
        }

        /// <summary>
        /// Leases a reusable cipher object initialized for encryption.
        /// </summary>
        /// <param name="key">Encryption key</param>
        /// <param name="iv">IV/Nonce</param>
        /// <returns>A lease supplying a crypto transform for encryption</returns>
        public ObjectPool<ICryptoTransform>.Lease<ICryptoTransform> EncryptionCipher(byte[] key, byte[] iv)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (iv == null) 
                throw new ArgumentNullException(nameof(iv));

            ObjectPool<ICryptoTransform>.Lease<ICryptoTransform> lease = _encryptorPool.Get();
            
            // Create a new transform since we can't reuse existing ones with different keys/IVs
            ICryptoTransform transform = CreateTransform(key, iv, true);
            
            return new ObjectPool<ICryptoTransform>.Lease<ICryptoTransform>(_encryptorPool, transform);
        }

        /// <summary>
        /// Leases a reusable cipher object initialized for decryption.
        /// </summary>
        /// <param name="key">Decryption key</param>
        /// <param name="iv">IV/Nonce</param>
        /// <returns>A lease supplying a crypto transform for decryption</returns>
        public ObjectPool<ICryptoTransform>.Lease<ICryptoTransform> DecryptionCipher(DestroyableSecretKey key, byte[] iv)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            
            return DecryptionCipher(key.GetRaw(), iv);
        }

        /// <summary>
        /// Leases a reusable cipher object initialized for decryption.
        /// </summary>
        /// <param name="key">Decryption key</param>
        /// <param name="iv">IV/Nonce</param>
        /// <returns>A lease supplying a crypto transform for decryption</returns>
        public ObjectPool<ICryptoTransform>.Lease<ICryptoTransform> DecryptionCipher(byte[] key, byte[] iv)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));

            ObjectPool<ICryptoTransform>.Lease<ICryptoTransform> lease = _decryptorPool.Get();
            
            // Create a new transform since we can't reuse existing ones with different keys/IVs
            ICryptoTransform transform = CreateTransform(key, iv, false);
            
            return new ObjectPool<ICryptoTransform>.Lease<ICryptoTransform>(_decryptorPool, transform);
        }

        private ICryptoTransform CreateTransform(byte[] key, byte[] iv, bool forEncryption)
        {
            switch (_algorithm)
            {
                case "AES-CTR":
                    return new AesCtrTransform(key, iv, forEncryption);
                case "AES-GCM":
                    return new AesGcmTransform(key, iv, forEncryption);
                case "AES-WRAP":
                    return new AesWrapTransform(key, forEncryption);
                default:
                    throw new NotSupportedException($"Unsupported algorithm: {_algorithm}");
            }
        }

        #region Custom Crypto Transforms

        /// <summary>
        /// Custom implementation of AES-CTR mode for .NET
        /// </summary>
        private class AesCtrTransform : ICryptoTransform
        {
            private readonly byte[] _key;
            private readonly byte[] _counter;
            private readonly bool _forEncryption;
            private readonly Aes _aes;
            private byte[] _counterBlock;
            private int _counterPosition;

            public AesCtrTransform(byte[] key, byte[] iv, bool forEncryption)
            {
                _key = key;
                _counter = new byte[16]; // AES block size
                _forEncryption = forEncryption; // In CTR mode, encryption and decryption are identical

                // Initialize counter 
                Array.Copy(iv, 0, _counter, 0, Math.Min(iv.Length, _counter.Length));

                // Initialize AES
                _aes = Aes.Create();
                _aes.Mode = CipherMode.ECB; // We'll implement CTR manually
                _aes.Padding = PaddingMode.None;
                _aes.Key = key;

                // Pre-allocate counter block
                _counterBlock = new byte[16];
                _counterPosition = 16; // Force regeneration on first use
            }

            public bool CanReuseTransform => false;
            public bool CanTransformMultipleBlocks => true;
            public int InputBlockSize => 16; // AES block size
            public int OutputBlockSize => 16; // AES block size

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                for (int i = 0; i < inputCount; i++)
                {
                    if (_counterPosition >= 16)
                        UpdateCounterBlock();

                    outputBuffer[outputOffset + i] = (byte)(inputBuffer[inputOffset + i] ^ _counterBlock[_counterPosition++]);
                }

                return inputCount;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                byte[] output = new byte[inputCount];
                
                if (inputCount > 0)
                    TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
                
                return output;
            }

            private void UpdateCounterBlock()
            {
                // Copy current counter to block
                Array.Copy(_counter, 0, _counterBlock, 0, 16);

                // Encrypt the counter block
                using (ICryptoTransform encryptor = _aes.CreateEncryptor())
                {
                    encryptor.TransformBlock(_counterBlock, 0, 16, _counterBlock, 0);
                }

                // Increment counter - start from the last byte and carry over
                for (int i = 15; i >= 0; i--)
                {
                    if (++_counter[i] != 0)
                        break;
                }

                // Reset position
                _counterPosition = 0;
            }

            public void Dispose()
            {
                _aes.Dispose();
                CryptographicOperations.ZeroMemory(_key);
                CryptographicOperations.ZeroMemory(_counter);
                CryptographicOperations.ZeroMemory(_counterBlock);
            }
        }

        /// <summary>
        /// Custom implementation of AES-GCM mode for .NET
        /// </summary>
        private class AesGcmTransform : ICryptoTransform
        {
            private readonly byte[] _key;
            private readonly byte[] _nonce;
            private readonly bool _forEncryption;
            private readonly AesGcm _aesGcm;
            private readonly byte[] _tag;

            public AesGcmTransform(byte[] key, byte[] nonce, bool forEncryption)
            {
                _key = key;
                _nonce = nonce;
                _forEncryption = forEncryption;
                _aesGcm = new AesGcm(key);
                _tag = new byte[16]; // AES-GCM tag size
            }

            public bool CanReuseTransform => false;
            public bool CanTransformMultipleBlocks => true;
            public int InputBlockSize => 1;
            public int OutputBlockSize => 1;

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                try
                {
                    if (_forEncryption)
                    {
                        _aesGcm.Encrypt(_nonce, inputBuffer.AsSpan(inputOffset, inputCount), 
                            outputBuffer.AsSpan(outputOffset, inputCount), _tag);
                    }
                    else
                    {
                        _aesGcm.Decrypt(_nonce, inputBuffer.AsSpan(inputOffset, inputCount),
                            _tag, outputBuffer.AsSpan(outputOffset, inputCount));
                    }
                    return inputCount;
                }
                catch (CryptographicException ex)
                {
                    throw new CryptographicException("AES-GCM operation failed", ex);
                }
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                byte[] output = new byte[inputCount];
                
                if (inputCount > 0)
                    TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
                
                return output;
            }

            public void Dispose()
            {
                _aesGcm.Dispose();
                CryptographicOperations.ZeroMemory(_key);
                CryptographicOperations.ZeroMemory(_nonce);
                CryptographicOperations.ZeroMemory(_tag);
            }
        }

        /// <summary>
        /// Transform for AES Key Wrapping (RFC 3394)
        /// </summary>
        private class AesWrapTransform : ICryptoTransform
        {
            private readonly byte[] _key;
            private readonly bool _forEncryption;

            public AesWrapTransform(byte[] key, bool forEncryption)
            {
                _key = key;
                _forEncryption = forEncryption;
            }

            public bool CanReuseTransform => false;
            public bool CanTransformMultipleBlocks => false;
            public int InputBlockSize => 8;
            public int OutputBlockSize => 8;

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                try
                {
                    byte[] result;
                    if (_forEncryption)
                    {
                        result = AesKeyWrap.Wrap(_key, inputBuffer);
                    }
                    else
                    {
                        result = AesKeyWrap.Unwrap(_key, inputBuffer);
                    }
                    
                    Buffer.BlockCopy(result, 0, outputBuffer, outputOffset, result.Length);
                    return result.Length;
                }
                catch (Exception ex)
                {
                    throw new CryptographicException("AES Key Wrap operation failed", ex);
                }
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                try
                {
                    if (inputCount == 0)
                        return Array.Empty<byte>();
                    
                    // Copy the input to a new buffer
                    byte[] input = new byte[inputCount];
                    Buffer.BlockCopy(inputBuffer, inputOffset, input, 0, inputCount);
                    
                    // Perform the operation
                    if (_forEncryption)
                    {
                        return AesKeyWrap.Wrap(_key, input);
                    }
                    else
                    {
                        return AesKeyWrap.Unwrap(_key, input);
                    }
                }
                catch (Exception ex)
                {
                    throw new CryptographicException("AES Key Wrap operation failed", ex);
                }
            }

            public void Dispose()
            {
                CryptographicOperations.ZeroMemory(_key);
            }
        }

        #endregion
    }
} 