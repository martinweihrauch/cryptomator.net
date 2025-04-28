using System;
using System.IO;
using CryptomatorLib; // Assuming Vault class is in this namespace
using CryptomatorLib.Api; // For DirectoryMetadata and exceptions

Console.WriteLine("CryptomatorLib Simple Encryption Example");

// --- Configuration --- 
// IMPORTANT: Replace with your actual paths!
const string sourceFolderPath = @"D:\EncryptionTestSource"; // Folder containing files/dirs to encrypt
const string vaultFolderPath = @"D:\EncryptionTestVault";   // Target folder where encrypted vault structure will be created
const string password = "your-super-secret-password";
// ---------------------

// Ensure target directory exists
Directory.CreateDirectory(vaultFolderPath);

string masterkeyFilePath = Path.Combine(vaultFolderPath, "masterkey.cryptomator");

try
{
    // --- Vault Setup ---
    byte[] masterkeyContent;
    if (!File.Exists(masterkeyFilePath))
    {
        Console.WriteLine($"Masterkey file not found. Creating new one at: {masterkeyFilePath}");
        masterkeyContent = Vault.CreateNewVaultKeyFileContent(password);
        File.WriteAllBytes(masterkeyFilePath, masterkeyContent);
        Console.WriteLine("New masterkey file created.");
    }
    else
    {
        Console.WriteLine($"Loading existing masterkey file from: {masterkeyFilePath}");
        masterkeyContent = File.ReadAllBytes(masterkeyFilePath);
    }

    Console.WriteLine("Loading vault...");
    // Load the vault using the key file content and password
    Vault vault = Vault.Load(masterkeyContent, password);
    Console.WriteLine("Vault loaded successfully.");

    // --- Recursive Encryption ---
    Console.WriteLine($"Starting encryption from '{sourceFolderPath}' to '{vaultFolderPath}'...");

    // Get root metadata and the physical path for the encrypted root content
    DirectoryMetadata rootMetadata = vault.GetRootDirectoryMetadata();
    string vaultRootContentPath = vault.GetRootDirectoryPath(); // Path like "d/XX/YYYY..."
    string fullVaultRootContentPath = Path.Combine(vaultFolderPath, vaultRootContentPath);
    Directory.CreateDirectory(fullVaultRootContentPath); // Ensure physical root content dir exists

    // Start recursive processing
    ProcessDirectory(vault, sourceFolderPath, fullVaultRootContentPath, rootMetadata);

    Console.WriteLine("Encryption process completed.");

}
catch (InvalidPassphraseException)
{
    Console.Error.WriteLine("ERROR: Invalid password provided for the vault.");
    Environment.Exit(1);
}
catch (AuthenticationFailedException authEx)
{
    Console.Error.WriteLine($"ERROR: Authentication failed. Masterkey file might be corrupt or password incorrect. {authEx.Message}");
    Environment.Exit(1);
}
catch (UnsupportedVaultFormatException formatEx)
{
    Console.Error.WriteLine($"ERROR: Unsupported vault format. {formatEx.Message}");
    Environment.Exit(1);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"An unexpected error occurred: {ex.Message}");
    Console.Error.WriteLine(ex.StackTrace);
    Environment.Exit(1);
}


/// <summary>
/// Recursively processes a directory, encrypting files and subdirectories.
/// </summary>
/// <param name="vault">The loaded Vault instance.</param>
/// <param name="sourceDir">The current source directory path.</param>
/// <param name="targetEncryptedPath">The physical path within the vault where the encrypted contents of sourceDir should be placed.</param>
/// <param name="parentDirMetadata">The DirectoryMetadata of the PARENT directory in the vault structure (used for encrypting names).</param>
static void ProcessDirectory(Vault vault, string sourceDir, string targetEncryptedPath, DirectoryMetadata parentDirMetadata)
{
    Console.WriteLine($"Processing directory: {sourceDir}");

    // --- Encrypt Files in Current Directory ---
    foreach (string sourceFile in Directory.GetFiles(sourceDir))
    {
        string plainName = Path.GetFileName(sourceFile);
        Console.WriteLine($"  Encrypting file: {plainName}");
        try
        {
            // Encrypt filename using parent directory's metadata
            string encryptedFilename = vault.EncryptFilename(plainName, parentDirMetadata);
            string targetFilePath = Path.Combine(targetEncryptedPath, encryptedFilename);

            // Encrypt content using streams
            using FileStream sourceStream = File.OpenRead(sourceFile);
            using FileStream targetStream = File.Create(targetFilePath);
            using Stream encryptingStream = vault.GetEncryptingStream(targetStream);

            sourceStream.CopyTo(encryptingStream); // This handles buffering and encryption
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR encrypting file {plainName}: {ex.Message}");
            // Decide whether to continue or stop on file error
        }
    }

    // --- Process Subdirectories --- 
    foreach (string sourceSubDir in Directory.GetDirectories(sourceDir))
    {
        string plainSubDirName = Path.GetFileName(sourceSubDir);
        Console.WriteLine($"  Processing subdirectory: {plainSubDirName}");
        try
        {
            // 1. Create metadata for the new directory
            DirectoryMetadata subDirMetadata = vault.CreateNewDirectoryMetadata();

            // 2. Encrypt the subdirectory name (using parent's metadata)
            // This determines the name of the *placeholder file* in the parent's encrypted path
            // string encryptedDirFilename = vault.EncryptFilename(plainSubDirName, parentDirMetadata);
            // NOTE: Cryptomator doesn't store directories as simple encrypted files. 
            // It uses the dirID embedded in the path and a dir.uvf file.

            // 3. Get the *actual encrypted path* for this new directory's content using its OWN metadata
            string encryptedSubDirPath = vault.GetDirectoryPath(subDirMetadata); // Path like d/YY/ZZZZ...
            string fullTargetSubDirPath = Path.Combine(vaultFolderPath, encryptedSubDirPath);

            // 4. Create the physical directory for the encrypted content
            Directory.CreateDirectory(fullTargetSubDirPath);

            // 5. Encrypt the new directory's metadata 
            byte[] encryptedMetadataBytes = vault.EncryptDirectoryMetadata(subDirMetadata);

            // 6. Write the dir.uvf file inside the encrypted directory path
            string dirUvfPath = Path.Combine(fullTargetSubDirPath, "dir.uvf");
            File.WriteAllBytes(dirUvfPath, encryptedMetadataBytes);
            Console.WriteLine($"    Created encrypted directory structure at: {fullTargetSubDirPath}");
            Console.WriteLine($"    Written metadata file: {dirUvfPath}");

            // 7. Recursively process the subdirectory
            // Pass the NEW metadata for the subdirectory as the parent for its children
            ProcessDirectory(vault, sourceSubDir, fullTargetSubDirPath, subDirMetadata);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR processing subdirectory {plainSubDirName}: {ex.Message}");
            // Decide whether to continue or stop on directory error
        }
    }
}
