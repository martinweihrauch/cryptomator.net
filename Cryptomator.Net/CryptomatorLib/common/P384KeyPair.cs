using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptomatorLib.Common
{
    /// <summary>
    /// Elliptic Curve Key Pair using the P-384 curve (secp384r1).
    /// </summary>
    public class P384KeyPair : IDisposable
    {
        private ECKeyPair _keyPair;
        private bool _disposed = false;

        /// <summary>
        /// Creates a new P384KeyPair with the given key pair
        /// </summary>
        /// <param name="keyPair">The underlying EC key pair</param>
        private P384KeyPair(ECKeyPair keyPair)
        {
            _keyPair = keyPair ?? throw new ArgumentNullException(nameof(keyPair));
        }

        /// <summary>
        /// Generates a new P-384 key pair.
        /// </summary>
        /// <returns>A new key pair</returns>
        public static P384KeyPair Generate()
        {
            ECKeyPair keyPair = ECKeyPair.Generate(ECCurve.NamedCurves.nistP384);
            return new P384KeyPair(keyPair);
        }

        /// <summary>
        /// Creates a key pair from the given key data.
        /// </summary>
        /// <param name="publicKeyBytes">DER formatted public key</param>
        /// <param name="privateKeyBytes">DER formatted private key</param>
        /// <returns>Created key pair</returns>
        public static P384KeyPair Create(byte[] publicKeyBytes, byte[] privateKeyBytes)
        {
            if (publicKeyBytes == null) throw new ArgumentNullException(nameof(publicKeyBytes));
            if (privateKeyBytes == null) throw new ArgumentNullException(nameof(privateKeyBytes));

            // Create a new ECDsa instance with the P-384 curve
            ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            
            // Import the private key
            ecdsa.ImportECPrivateKey(privateKeyBytes, out _);
            
            // Verify that the public key matches
            byte[] expectedPublicKey = ecdsa.ExportSubjectPublicKeyInfo();
            if (!ECKeyPair.VerifyPublicKey(publicKeyBytes, ECCurve.NamedCurves.nistP384))
            {
                throw new ArgumentException("Invalid public key or does not match private key", nameof(publicKeyBytes));
            }

            return new P384KeyPair(new ECKeyPair(ecdsa));
        }

        /// <summary>
        /// Exports the public key in DER format
        /// </summary>
        /// <returns>The public key bytes</returns>
        public byte[] ExportPublicKey()
        {
            return _keyPair.ExportPublicKey();
        }

        /// <summary>
        /// Exports the private key in PKCS#8 format
        /// </summary>
        /// <returns>The private key bytes</returns>
        public byte[] ExportPrivateKey()
        {
            return _keyPair.ExportPrivateKeyPkcs8();
        }

        /// <summary>
        /// Signs the provided data using SHA-384 with ECDSA
        /// </summary>
        /// <param name="data">The data to sign</param>
        /// <returns>The signature</returns>
        public byte[] Sign(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (_disposed)
                throw new ObjectDisposedException(nameof(P384KeyPair));

            // Use SHA-384 for P-384 curve as per best practices
            return _keyPair.PrivateKey.SignData(data, HashAlgorithmName.SHA384);
        }

        /// <summary>
        /// Verifies a signature against the provided data
        /// </summary>
        /// <param name="data">The data that was signed</param>
        /// <param name="signature">The signature to verify</param>
        /// <returns>True if the signature is valid, false otherwise</returns>
        public bool Verify(byte[] data, byte[] signature)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (signature == null)
                throw new ArgumentNullException(nameof(signature));

            if (_disposed)
                throw new ObjectDisposedException(nameof(P384KeyPair));

            // Use SHA-384 for P-384 curve as per best practices
            return _keyPair.PrivateKey.VerifyData(data, signature, HashAlgorithmName.SHA384);
        }

        /// <summary>
        /// Stores the key pair in a PKCS#12 file
        /// </summary>
        /// <param name="path">The path to save the file</param>
        /// <param name="password">The password to protect the key material</param>
        public void Store(string path, char[] password)
        {
            if (string.IsNullOrEmpty(path))
                throw new ArgumentNullException(nameof(path));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            if (_disposed)
                throw new ObjectDisposedException(nameof(P384KeyPair));

            // Create a self-signed certificate to store the key pair
            var builder = new X509CertBuilder()
                .WithSubjectName("CN=P384KeyPair")
                .WithIssuerName("CN=P384KeyPair")
                .WithKeyPair(_keyPair)
                .WithValidityDuration(3650); // 10 years

            X509Certificate2 cert = builder.Build();

            // Export with private key to PKCS#12 format
            byte[] certData = cert.Export(X509ContentType.Pkcs12, new string(password));

            // Write the file
            File.WriteAllBytes(path, certData);
        }

        /// <summary>
        /// Loads a key pair from a PKCS#12 file
        /// </summary>
        /// <param name="path">The path to the PKCS#12 file</param>
        /// <param name="password">The password protecting the key material</param>
        /// <returns>The loaded key pair</returns>
        /// <exception cref="Pkcs12PasswordException">If the supplied password is incorrect</exception>
        /// <exception cref="Pkcs12Exception">If any cryptographic operation fails</exception>
        public static P384KeyPair Load(string path, char[] password)
        {
            if (string.IsNullOrEmpty(path))
                throw new ArgumentNullException(nameof(path));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            try
            {
                // Read the certificate from the file
                X509Certificate2 cert = new X509Certificate2(path, new string(password), 
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

                // Ensure it has a private key
                if (!cert.HasPrivateKey)
                    throw new Pkcs12Exception("Certificate does not contain a private key");

                // Get the ECDsa key
                ECDsa ecdsa = cert.GetECDsaPrivateKey();
                if (ecdsa == null)
                    throw new Pkcs12Exception("Certificate does not contain an EC key");

                // Verify it's a P-384 key
                ECParameters parameters = ecdsa.ExportParameters(false);
                if (parameters.Curve.Oid.FriendlyName != "nistP384")
                    throw new Pkcs12Exception("Certificate does not contain a P-384 key");

                // Create the key pair
                return new P384KeyPair(new ECKeyPair(ecdsa));
            }
            catch (CryptographicException ex)
            {
                throw new Pkcs12PasswordException("Invalid password", ex);
            }
            catch (Exception ex) when (!(ex is Pkcs12Exception) && !(ex is Pkcs12PasswordException))
            {
                throw new Pkcs12Exception("Failed to load key pair", ex);
            }
        }

        /// <summary>
        /// Disposes the key pair
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _keyPair?.Dispose();
                _keyPair = null;
                _disposed = true;
            }
        }
    }
}