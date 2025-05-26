using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Jose;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Starting Minimal Reproducible Example for jose-jwt...");

        string password = "your-super-secret-password"; // Same as in your UvfConsole
        int pbkdf2Iterations = 64000;
        int saltSizeBytes = 16;
        JweAlgorithm keyManagementAlgorithm = JweAlgorithm.PBES2_HS512_A256KW;
        JweEncryption contentEncryptionAlgorithm = JweEncryption.A256GCM;

        string dummyPayloadJson = "{\"message\":\"hello world\", \"timestamp\":\"" + DateTime.UtcNow.ToLongTimeString() + "\"}";
        byte[] salt = RandomNumberGenerator.GetBytes(saltSizeBytes);

        Console.WriteLine($"MRE - Password Length: {password.Length}");
        using (var sha256 = SHA256.Create())
        {
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            Console.WriteLine($"MRE - Password SHA256: {Convert.ToBase64String(hashedBytes)}");
        }
        Console.WriteLine($"MRE - PBKDF2 Iterations (p2c): {pbkdf2Iterations}");
        Console.WriteLine($"MRE - Generated Salt (p2s): {Base64Url.Encode(salt)}");
        Console.WriteLine($"MRE - KeyManagementAlgorithm: {keyManagementAlgorithm}");
        Console.WriteLine($"MRE - ContentEncryptionAlgorithm: {contentEncryptionAlgorithm}");
        Console.WriteLine($"MRE - Payload: {dummyPayloadJson}");

        var extraHeaders = new Dictionary<string, object>
        {
            { "p2s", Base64Url.Encode(salt) },
            { "p2c", pbkdf2Iterations }
        };

        var settings = new JwtSettings();
        string jweString = "";

        try
        {
            Console.WriteLine("MRE - Attempting JWT.Encode...");
            jweString = JWT.Encode(dummyPayloadJson, password, keyManagementAlgorithm, contentEncryptionAlgorithm, extraHeaders: extraHeaders, settings: settings);
            Console.WriteLine($"MRE - JWT.Encode successful. JWE String (first 30 chars): {(jweString.Length > 30 ? jweString.Substring(0, 30) : jweString)}...");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"MRE - ERROR during JWT.Encode: {ex.ToString()}");
            Console.WriteLine("MRE - Test cannot continue.");
            return;
        }

        Console.WriteLine("MRE - Attempting JWT.Decode...");
        try
        {
            string decryptedPayload = JWT.Decode(jweString, password, settings: settings);
            Console.WriteLine("MRE - JWT.Decode successful!");
            Console.WriteLine($"MRE - Decrypted Payload: {decryptedPayload}");
        }
        catch (Jose.IntegrityException intEx)
        {
            Console.WriteLine($"MRE - INTEGRITY EXCEPTION during JWT.Decode: {intEx.ToString()}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"MRE - OTHER EXCEPTION during JWT.Decode: {ex.ToString()}");
        }

        Console.WriteLine("MRE - Test finished.");
    }
}
