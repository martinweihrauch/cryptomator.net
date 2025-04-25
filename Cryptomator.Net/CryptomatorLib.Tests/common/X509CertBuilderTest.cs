using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Common;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptomatorLib.Tests.Common
{
    [TestClass]
    public class X509CertBuilderTest
    {
        [TestMethod]
        [DisplayName("Init() With RSA Key And EC Signature")]
        public void TestInitWithInvalidKeyPair()
        {
            using (RSA rsa = RSA.Create())
            {
                var keyPair = new AsymmetricCryptoKeyPair(rsa.ExportParameters(false), rsa.ExportParameters(true));
                string signingAlg = "SHA256withECDSA";

                Assert.ThrowsException<ArgumentException>(() =>
                {
                    X509CertBuilder.Init(keyPair, signingAlg);
                });
            }
        }

        [TestMethod]
        [DisplayName("Init() With RSA Key And RSA Signature")]
        public void TestInitWithRSAKeyPair()
        {
            using (RSA rsa = RSA.Create())
            {
                var keyPair = new AsymmetricCryptoKeyPair(rsa.ExportParameters(false), rsa.ExportParameters(true));
                string signingAlg = "SHA256withRSA";

                // Should not throw
                X509CertBuilder.Init(keyPair, signingAlg);
            }
        }

        [TestMethod]
        [DisplayName("Init() With EC Key And EC Signature")]
        public void TestInitWithECKeyPair()
        {
            using (ECDsa ecdsa = ECDsa.Create())
            {
                var keyPair = new AsymmetricCryptoKeyPair(ecdsa.ExportParameters(false), ecdsa.ExportParameters(true));
                string signingAlg = "SHA256withECDSA";

                // Should not throw
                X509CertBuilder.Init(keyPair, signingAlg);
            }
        }

        [TestClass]
        public class WithInitialized
        {
            private AsymmetricCryptoKeyPair _keyPair;
            private X509CertBuilder _builder;

            [TestInitialize]
            public void Setup()
            {
                using (ECDsa ecdsa = ECDsa.Create())
                {
                    this._keyPair = new AsymmetricCryptoKeyPair(ecdsa.ExportParameters(false), ecdsa.ExportParameters(true));
                    this._builder = X509CertBuilder.Init(_keyPair, "SHA256withECDSA");
                }
            }

            [TestMethod]
            [DisplayName("Set Invalid Issuer")]
            public void TestWithInvalidIssuer()
            {
                Assert.ThrowsException<ArgumentException>(() =>
                {
                    _builder.WithIssuerName("Test");
                });
            }

            [TestMethod]
            [DisplayName("Set Invalid Subject")]
            public void TestWithInvalidSubject()
            {
                Assert.ThrowsException<ArgumentException>(() =>
                {
                    _builder.WithSubjectName("Test");
                });
            }

            [TestMethod]
            [DisplayName("Build() With Missing Issuer")]
            public void TestBuildWithMissingIssuer()
            {
                _builder.WithSubjectName("CN=Test")
                        .WithValidityPeriod(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));

                Assert.ThrowsException<InvalidOperationException>(() =>
                {
                    _builder.Build();
                });
            }

            [TestMethod]
            [DisplayName("Build() With Missing Subject")]
            public void TestBuildWithMissingSubject()
            {
                _builder.WithIssuerName("CN=Test")
                        .WithValidityPeriod(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));

                Assert.ThrowsException<InvalidOperationException>(() =>
                {
                    _builder.Build();
                });
            }

            [TestMethod]
            [DisplayName("Build() With Missing NotBefore")]
            public void TestBuildWithMissingNotBefore()
            {
                _builder.WithIssuerName("CN=Test")
                        .WithSubjectName("CN=Test");
                // Not setting validity period

                Assert.ThrowsException<InvalidOperationException>(() =>
                {
                    _builder.Build();
                });
            }

            [TestMethod]
            [DisplayName("Build() With Invalid NotAfter")]
            public void TestBuildWithInvalidNotAfter()
            {
                var now = DateTimeOffset.UtcNow;
                _builder.WithIssuerName("CN=Test")
                        .WithSubjectName("CN=Test");
                
                Assert.ThrowsException<ArgumentException>(() =>
                {
                    _builder.WithValidityPeriod(now, now.AddSeconds(-1));
                });
            }

            [TestMethod]
            [DisplayName("Build() With All Params Set")]
            public void TestBuild()
            {
                X509Certificate2 cert = _builder
                        .WithIssuerName("CN=Test")
                        .WithSubjectName("CN=Test")
                        .WithValidityPeriod(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1))
                        .Build();

                Assert.IsNotNull(cert);

                // Verify the certificate
                bool isValid = cert.Verify();
                Assert.IsTrue(isValid);

                // Verify validity dates
                Assert.IsTrue(DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter);
            }
        }

        [TestMethod]
        public void TestBasicCertificateCreation()
        {
            // Create a key pair
            var keyPair = ECKeyPair.Generate(ECCurve.NamedCurves.nistP256);
            
            // Create a certificate
            var cert = new X509CertBuilder()
                .WithSubjectName("CN=Test Certificate")
                .WithIssuerName("CN=Test Certificate")
                .WithValidityDuration(365)
                .Build();
            
            // Verify the certificate
            Assert.IsNotNull(cert);
            Assert.AreEqual("CN=Test Certificate", cert.Subject);
            Assert.AreEqual("CN=Test Certificate", cert.Issuer);
            Assert.IsTrue(cert.HasPrivateKey);
            
            // Verify dates - allow a small tolerance for test execution time
            var now = DateTimeOffset.UtcNow;
            Assert.IsTrue((now - cert.NotBefore).TotalSeconds < 10);
            Assert.IsTrue(Math.Abs((now.AddDays(365) - cert.NotAfter).TotalSeconds) < 10);
        }
        
        [TestMethod]
        public void TestCAFlaggedCertificateCreation()
        {
            // Create a key pair
            var keyPair = ECKeyPair.Generate(ECCurve.NamedCurves.nistP256);
            
            // Create a CA certificate
            var cert = new X509CertBuilder()
                .WithSubjectName("CN=Test CA")
                .WithIssuerName("CN=Test CA")
                .WithValidityDuration(3650)
                .WithKeyUsage(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)
                .WithCA(true)
                .Build();
            
            // Verify the certificate
            Assert.IsNotNull(cert);
            Assert.AreEqual("CN=Test CA", cert.Subject);
            
            // Verify it's a CA certificate by checking basic constraints extension
            var basicConstraints = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;
            Assert.IsNotNull(basicConstraints);
            Assert.IsTrue(basicConstraints.CertificateAuthority);
            
            // Verify key usage extension
            var keyUsage = cert.Extensions["2.5.29.15"] as X509KeyUsageExtension;
            Assert.IsNotNull(keyUsage);
            Assert.IsTrue((keyUsage.KeyUsages & X509KeyUsageFlags.KeyCertSign) != 0);
            Assert.IsTrue((keyUsage.KeyUsages & X509KeyUsageFlags.CrlSign) != 0);
        }
        
        [TestMethod]
        public void TestWithValidityDatesExplicit()
        {
            // Create a key pair
            var keyPair = ECKeyPair.Generate(ECCurve.NamedCurves.nistP256);
            
            // Set explicit dates
            var notBefore = new DateTimeOffset(2023, 1, 1, 0, 0, 0, TimeSpan.Zero);
            var notAfter = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
            
            // Create a certificate with explicit dates
            var cert = new X509CertBuilder()
                .WithSubjectName("CN=Test Certificate")
                .WithIssuerName("CN=Test Certificate")
                .WithValidityPeriod(notBefore, notAfter)
                .Build();
            
            // Verify dates
            Assert.AreEqual(notBefore.DateTime, cert.NotBefore);
            Assert.AreEqual(notAfter.DateTime, cert.NotAfter);
        }
        
        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void TestMissingIssuerName()
        {
            // Create a key pair
            var keyPair = ECKeyPair.Generate(ECCurve.NamedCurves.nistP256);
            
            // Try to create a certificate without setting the issuer name
            var cert = new X509CertBuilder()
                .WithSubjectName("CN=Test Certificate")
                .WithValidityDuration(365)
                .Build();
        }
        
        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void TestMissingSubjectName()
        {
            // Create a key pair
            var keyPair = ECKeyPair.Generate(ECCurve.NamedCurves.nistP256);
            
            // Try to create a certificate without setting the subject name
            var cert = new X509CertBuilder()
                .WithIssuerName("CN=Test Certificate")
                .WithValidityDuration(365)
                .Build();
        }
        
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestInvalidDateRange()
        {
            // Create a key pair
            var keyPair = ECKeyPair.Generate(ECCurve.NamedCurves.nistP256);
            
            // Set invalid date range (end before start)
            var notBefore = new DateTimeOffset(2023, 1, 1, 0, 0, 0, TimeSpan.Zero);
            var notAfter = new DateTimeOffset(2022, 1, 1, 0, 0, 0, TimeSpan.Zero);
            
            // Try to create a certificate with invalid date range
            var cert = new X509CertBuilder()
                .WithSubjectName("CN=Test Certificate")
                .WithIssuerName("CN=Test Certificate")
                .WithValidityPeriod(notBefore, notAfter)
                .Build();
        }
        
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestNegativeDuration()
        {
            // Create a key pair
            var keyPair = ECKeyPair.Generate(ECCurve.NamedCurves.nistP256);
            
            // Try to create a certificate with negative duration
            var cert = new X509CertBuilder()
                .WithSubjectName("CN=Test Certificate")
                .WithIssuerName("CN=Test Certificate")
                .WithValidityDuration(-365)
                .Build();
        }
    }
}