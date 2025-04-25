using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptomatorLib.Common;
using System;
using System.Security.Cryptography;
using Moq;

namespace CryptomatorLib.Tests.Common
{
    [TestClass]
    public class ReseedingSecureRandomTest
    {
        private Mock<RandomNumberGenerator> _seeder;
        private Mock<RandomNumberGenerator> _csprng;

        [TestInitialize]
        public void Setup()
        {
            _seeder = new Mock<RandomNumberGenerator>();
            _csprng = new Mock<RandomNumberGenerator>();

            // Setup mock behavior for seeder.GetBytes method
            _seeder.Setup(s => s.GetBytes(It.IsAny<byte[]>()))
                .Callback<byte[]>((bytes) =>
                {
                    // Fill with zeros (simulating deterministic behavior for testing)
                    Array.Clear(bytes, 0, bytes.Length);
                });
        }

        [TestMethod]
        [DisplayName("Test Reseed After Limit Reached")]
        public void TestReseedAfterLimitReached()
        {
            // Create a reseeding random number generator with 10 bytes limit and 3 bytes seed
            var rand = new ReseedingSecureRandom(_seeder.Object, _csprng.Object, 10, 3);

            // Verify that the seeder hasn't been called yet
            _seeder.Verify(s => s.GetBytes(It.IsAny<byte[]>()), Times.Never);

            // Generate 4 bytes - should trigger initial seeding
            byte[] buffer1 = new byte[4];
            rand.GetBytes(buffer1);
            _seeder.Verify(s => s.GetBytes(It.IsAny<byte[]>()), Times.Once);

            // Generate 4 more bytes - should not trigger reseeding yet
            byte[] buffer2 = new byte[4];
            rand.GetBytes(buffer2);
            _seeder.Verify(s => s.GetBytes(It.IsAny<byte[]>()), Times.Once);

            // Generate 4 more bytes - should trigger reseeding (now at 12 bytes total)
            byte[] buffer3 = new byte[4];
            rand.GetBytes(buffer3);
            _seeder.Verify(s => s.GetBytes(It.IsAny<byte[]>()), Times.Exactly(2));
        }
    }
}