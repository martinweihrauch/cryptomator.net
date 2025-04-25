using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CryptomatorLib.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptomatorLib.Tests.Common
{
    [TestClass]
    public class X509CertBuilderTests
    {
        [TestMethod]
        public void Build_WithDefaultSettings_CreatesValidCertificate()
        {
            // Arrange
            var builder = new X509CertBuilder()
                .WithSubjectName("CN=Test")
                .WithIssuerName("CN=Test");

            // Act
            var cert = builder.Build();

            // Assert
            Assert.IsNotNull(cert);
            Assert.AreEqual("CN=Test", cert.Subject);
            Assert.AreEqual("CN=Test", cert.Issuer);
            Assert.IsTrue(cert.HasPrivateKey);
            Assert.IsFalse(cert.Extensions.Cast<X509Extension>().Any(e => e is X509BasicConstraintsExtension ext && ext.CertificateAuthority));
        }

        [TestMethod]
        public void Build_WithCAFlag_CreatesCACertificate()
        {
            // Arrange
            var builder = new X509CertBuilder()
                .WithSubjectName("CN=TestCA")
                .WithIssuerName("CN=TestCA")
                .WithCA(true);

            // Act
            var cert = builder.Build();

            // Assert
            Assert.IsNotNull(cert);
            var bcExt = cert.Extensions.Cast<X509Extension>()
                .FirstOrDefault(e => e is X509BasicConstraintsExtension) as X509BasicConstraintsExtension;

            Assert.IsNotNull(bcExt);
            Assert.IsTrue(bcExt.CertificateAuthority);

            // Check that key usage includes certificate signing
            var kuExt = cert.Extensions.Cast<X509Extension>()
                .FirstOrDefault(e => e is X509KeyUsageExtension) as X509KeyUsageExtension;

            Assert.IsNotNull(kuExt);
            Assert.IsTrue((kuExt.KeyUsages & X509KeyUsageFlags.KeyCertSign) == X509KeyUsageFlags.KeyCertSign);
        }

        [TestMethod]
        public void Build_WithCustomValidity_SetsCorrectDates()
        {
            // Arrange
            var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
            var notAfter = DateTimeOffset.UtcNow.AddYears(2);

            var builder = new X509CertBuilder()
                .WithSubjectName("CN=Test")
                .WithIssuerName("CN=Test")
                .WithValidityPeriod(notBefore, notAfter);

            // Act
            var cert = builder.Build();

            // Assert
            Assert.IsNotNull(cert);
            // Check that dates are within a minute (accounting for execution time)
            Assert.IsTrue((cert.NotBefore - notBefore.DateTime).TotalMinutes < 1);
            Assert.IsTrue((cert.NotAfter - notAfter.DateTime).TotalMinutes < 1);
        }

        [TestMethod]
        public void Build_WithDuration_SetsCorrectExpiryDate()
        {
            // Arrange
            var durationDays = 30;
            var expectedExpiry = DateTimeOffset.UtcNow.AddDays(durationDays);

            var builder = new X509CertBuilder()
                .WithSubjectName("CN=Test")
                .WithIssuerName("CN=Test")
                .WithValidityDuration(durationDays);

            // Act
            var cert = builder.Build();

            // Assert
            Assert.IsNotNull(cert);
            // Check that expiry date is within a day (accounting for execution time)
            Assert.IsTrue((cert.NotAfter - expectedExpiry.DateTime).TotalDays < 1);
        }

        [TestMethod]
        public void Build_WithCustomKeyPair_UsesProvidedKey()
        {
            // Arrange
            var keyPair = ECKeyPair.Generate(ECCurve.NamedCurves.nistP256);
            var pubKeyBytes = keyPair.ExportPublicKey();

            var builder = new X509CertBuilder()
                .WithSubjectName("CN=Test")
                .WithIssuerName("CN=Test")
                .WithKeyPair(keyPair);

            // Act
            var cert = builder.Build();

            // Assert
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);

            // Compare public key information
            using var pubKey = cert.GetECDsaPublicKey();
            var certPubKeyBytes = pubKey.ExportSubjectPublicKeyInfo();

            // The exported public keys should match
            CollectionAssert.AreEqual(pubKeyBytes, certPubKeyBytes);
        }

        [TestMethod]
        public void Build_WithCustomKeyUsage_SetsCorrectKeyUsage()
        {
            // Arrange
            var keyUsage = X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyAgreement;

            var builder = new X509CertBuilder()
                .WithSubjectName("CN=Test")
                .WithIssuerName("CN=Test")
                .WithKeyUsage(keyUsage);

            // Act
            var cert = builder.Build();

            // Assert
            Assert.IsNotNull(cert);
            var kuExt = cert.Extensions.Cast<X509Extension>()
                .FirstOrDefault(e => e is X509KeyUsageExtension) as X509KeyUsageExtension;

            Assert.IsNotNull(kuExt);
            Assert.AreEqual(keyUsage, kuExt.KeyUsages);
        }

        [TestMethod]
        public void Build_WithoutSubjectName_ThrowsInvalidOperationException()
        {
            // Arrange
            var builder = new X509CertBuilder()
                .WithIssuerName("CN=Test");

            // Act & Assert
            var exception = Assert.ThrowsException<InvalidOperationException>(() => builder.Build());
            StringAssert.Contains(exception.Message, "Subject name is required");
        }

        [TestMethod]
        public void Build_WithoutIssuerName_ThrowsInvalidOperationException()
        {
            // Arrange
            var builder = new X509CertBuilder()
                .WithSubjectName("CN=Test");

            // Act & Assert
            var exception = Assert.ThrowsException<InvalidOperationException>(() => builder.Build());
            StringAssert.Contains(exception.Message, "Issuer name is required");
        }

        [TestMethod]
        [DataRow(-1)]
        [DataRow(-100)]
        public void WithValidityDuration_WithNegativeDuration_ThrowsArgumentException(int duration)
        {
            // Arrange
            var builder = new X509CertBuilder();

            // Act & Assert
            var exception = Assert.ThrowsException<ArgumentException>(() => builder.WithValidityDuration(duration));
            StringAssert.Contains(exception.Message, "Duration cannot be negative");
        }

        [TestMethod]
        public void WithValidityPeriod_WithInvalidDates_ThrowsArgumentException()
        {
            // Arrange
            var builder = new X509CertBuilder();
            var notBefore = DateTimeOffset.UtcNow;
            var notAfter = notBefore.AddDays(-1); // End date before start date

            // Act & Assert
            var exception = Assert.ThrowsException<ArgumentException>(() =>
                builder.WithValidityPeriod(notBefore, notAfter));
            StringAssert.Contains(exception.Message, "End date must be after start date");
        }
    }
}