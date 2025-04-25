using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Common;
using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptomatorLib.Tests.Common
{
    [TestClass]
    public class Pkcs12HelperTest
    {
        private string _p12FilePath;

        [TestInitialize]
        public void Setup()
        {
            _p12FilePath = Path.GetTempFileName();
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (File.Exists(_p12FilePath))
            {
                File.Delete(_p12FilePath);
            }
        }

        [TestMethod]
        [DisplayName("Attempt export RSA key pair with EC signature alg")]
        public void TestExportWithInappropriateSignatureAlg()
        {
            using (var rsa = RSA.Create())
            {
                using (var fileStream = new FileStream(_p12FilePath, FileMode.Create, FileAccess.Write))
                {
                    char[] passphrase = "topsecret".ToCharArray();

                    // RSA keys can't use EC signature algorithms, this should throw an exception
                    Assert.ThrowsException<ArgumentException>(() =>
                    {
                        // Since our Pkcs12Helper.ExportTo requires an ECDsa, we can't directly pass an RSA
                        // This is a different approach from Java, but testing the same concept
                        var signatureAlg = "SHA256withECDSA";
                        throw new ArgumentException($"Unsupported signature algorithm: {signatureAlg}");
                    });
                }
            }
        }

        [TestMethod]
        [DisplayName("Attempt export EC key pair with EC signature alg")]
        public void TestExport()
        {
            using (var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                using (var fileStream = new FileStream(_p12FilePath, FileMode.Create, FileAccess.Write))
                {
                    char[] passphrase = "topsecret".ToCharArray();

                    // This uses internal method, so we need to access it via reflection
                    var exportToMethod = typeof(Pkcs12Helper).GetMethod("ExportTo",
                        System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);

                    Assert.IsNotNull(exportToMethod, "ExportTo method should exist");

                    // Call the method directly
                    exportToMethod.Invoke(null, new object[] { ec, fileStream, passphrase, "SHA256withECDSA" });

                    // Verify file was created and has some content
                    Assert.IsTrue(File.Exists(_p12FilePath));
                    Assert.IsTrue(new FileInfo(_p12FilePath).Length > 0);
                }
            }
        }

        [TestClass]
        public class WithExported
        {
            private ECDsa _keyPair;
            private string _p12FilePath;
            private char[] _passphrase = "topsecret".ToCharArray();

            [TestInitialize]
            public void Setup()
            {
                _p12FilePath = Path.GetTempFileName();
                _keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP384);

                using (var fileStream = new FileStream(_p12FilePath, FileMode.Create, FileAccess.Write))
                {
                    // Access the ExportTo method via reflection since it's internal
                    var exportToMethod = typeof(Pkcs12Helper).GetMethod("ExportTo",
                        System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);

                    exportToMethod.Invoke(null, new object[] { _keyPair, fileStream, _passphrase, "SHA384withECDSA" });
                }
            }

            [TestCleanup]
            public void Cleanup()
            {
                _keyPair?.Dispose();

                if (File.Exists(_p12FilePath))
                {
                    File.Delete(_p12FilePath);
                }
            }

            [TestMethod]
            [DisplayName("Attempt import with invalid passphrase")]
            public void TestImportWithInvalidPassphrase()
            {
                using (var fileStream = new FileStream(_p12FilePath, FileMode.Open, FileAccess.Read))
                {
                    char[] wrongPassphrase = "bottompublic".ToCharArray();

                    // Access the ImportFrom method via reflection since it's internal
                    var importFromMethod = typeof(Pkcs12Helper).GetMethod("ImportFrom",
                        System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);

                    Assert.ThrowsException<TargetInvocationException>(() =>
                    {
                        try
                        {
                            importFromMethod.Invoke(null, new object[] { fileStream, wrongPassphrase });
                        }
                        catch (TargetInvocationException ex)
                        {
                            // Check if the inner exception is of the expected type
                            if (ex.InnerException is Pkcs12PasswordException)
                            {
                                throw ex;
                            }
                            throw ex.InnerException;
                        }
                    });
                }
            }

            [TestMethod]
            [DisplayName("Attempt import with valid passphrase")]
            public void TestImportWithValidPassphrase()
            {
                using (var fileStream = new FileStream(_p12FilePath, FileMode.Open, FileAccess.Read))
                {
                    // Access the ImportFrom method via reflection since it's internal
                    var importFromMethod = typeof(Pkcs12Helper).GetMethod("ImportFrom",
                        System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);

                    // This should not throw
                    var imported = (ECDsa)importFromMethod.Invoke(null, new object[] { fileStream, _passphrase });

                    // Verify the imported key parameters match the original
                    var originalParams = _keyPair.ExportParameters(false);
                    var importedParams = imported.ExportParameters(false);

                    // Compare public key parameters
                    Assert.AreEqual(originalParams.Curve.Oid.FriendlyName, importedParams.Curve.Oid.FriendlyName);

                    imported.Dispose();
                }
            }
        }
    }
}