using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UvfLib.Tests.Api
{
    [TestClass]
    public class Base64DecodingTests
    {
        // Helper method to convert URL-safe Base64 to standard Base64
        private static string FixBase64(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            string result = input;

            // Handle URL-safe Base64 by replacing '-' with '+' and '_' with '/'
            result = result.Replace('-', '+').Replace('_', '/');

            // Add padding if needed
            switch (result.Length % 4)
            {
                case 2: result += "=="; break;
                case 3: result += "="; break;
            }

            return result;
        }

        [TestMethod]
        [DisplayName("Test URL-Safe Base64 Decoding")]
        public void TestUrlSafeBase64Decoding()
        {
            // Test with specific strings from the failed tests
            string[] testStrings = new string[]
            {
                "HDm38i",      // initialSeed
                "QBsJFo",      // latestSeed
                "NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8", // kdfSalt
                "ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs", // seed value
                "Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y", // seed value
                "fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU", // seed value for test
                "HE4OP-2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY"  // kdfSalt for test
            };

            foreach (string testString in testStrings)
            {
                string fixedString = FixBase64(testString);

                // Output the strings for debugging
                Console.WriteLine($"Original: {testString}");
                Console.WriteLine($"Fixed:    {fixedString}");

                try
                {
                    // This should not throw
                    byte[] decoded = Convert.FromBase64String(fixedString);
                    Console.WriteLine($"Successfully decoded with length: {decoded.Length}");

                    // Make sure we get valid data back
                    Assert.IsNotNull(decoded);
                    Assert.IsTrue(decoded.Length > 0);
                }
                catch (Exception ex)
                {
                    Assert.Fail($"Failed to decode '{testString}' -> '{fixedString}': {ex.Message}");
                }
            }
        }

        [TestMethod]
        [DisplayName("Test End-to-End Base64 Encoding-Decoding")]
        public void TestEndToEndBase64EncodingDecoding()
        {
            // Test with random data of different lengths
            int[] testSizes = new int[] { 3, 4, 5, 6, 7, 8, 16, 32 };

            foreach (int size in testSizes)
            {
                // Generate random data
                byte[] original = new byte[size];
                new Random().NextBytes(original);

                // Encode to URL-safe Base64
                string base64 = Convert.ToBase64String(original)
                    .Replace('+', '-')
                    .Replace('/', '_')
                    .TrimEnd('=');

                // Now decode back
                string standardBase64 = FixBase64(base64);
                byte[] decoded = Convert.FromBase64String(standardBase64);

                // Verify
                Assert.AreEqual(original.Length, decoded.Length, $"Length mismatch for size {size}");
                CollectionAssert.AreEqual(original, decoded, $"Data mismatch for size {size}");
            }
        }
    }
}