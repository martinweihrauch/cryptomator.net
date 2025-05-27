using UvfLib; // Assuming Vault class is in this namespace
using UvfLib.Api; // For DirectoryMetadata and exceptions
using System.Diagnostics; // For Stopwatch
using System.Linq; // For LINQ methods

// --- Configuration --- 
// IMPORTANT: Replace with your actual paths!
const string sourceFolderPath = @"D:\temp\EncryptionTestSource"; // Folder containing files/dirs to encrypt
const string vaultFolderPath = @"D:\temp\EncryptionTestVault";   // Target folder where encrypted vault structure will be created
const string decryptedFolderPath = @"D:\temp\EncryptionTestDecrypted"; // Target folder for decrypted content
const string password = "your-super-secret-password";
// ---------------------

// Represents the main vault file, typically "vault.uvf"
// const string masterkeyFileName = "masterkey.cryptomator"; // Old name
const string vaultFileName = "vault.uvf"; // New name for JWE masterkey

// Stopwatch for overall operation
Stopwatch overallStopwatch = new Stopwatch();
long totalBytesProcessedOverall = 0;

// Main execution
if (args.Length == 0)
{
    Console.WriteLine("Usage: UvfConsole <encrypt|decrypt>");
    return;
}

string mode = args[0].ToLowerInvariant();

// Ensure vault directory exists
Directory.CreateDirectory(vaultFolderPath);

// string masterkeyFilePath = Path.Combine(vaultFolderPath, masterkeyFileName);
string vaultFilePath = Path.Combine(vaultFolderPath, vaultFileName);
byte[] vaultFileContent;

if (mode == "encrypt")
{
    // Ensure source directory exists for encryption
    if (!Directory.Exists(sourceFolderPath))
    {
        Console.Error.WriteLine($"ERROR: Source folder not found at {sourceFolderPath}. Cannot encrypt.");
        return;
    }
    Console.WriteLine($"Starting encryption: {sourceFolderPath} -> {vaultFolderPath}");

    if (File.Exists(vaultFilePath))
    {
        Console.WriteLine($"Vault file found at: {vaultFilePath}. Loading existing vault.");
        vaultFileContent = File.ReadAllBytes(vaultFilePath);
    }
    else
    {
        Console.WriteLine($"Vault file not found. Creating new one at: {vaultFilePath}");
        vaultFileContent = Vault.CreateNewUvfVaultFileContent(password); // Using new UVF method
        File.WriteAllBytes(vaultFilePath, vaultFileContent);
        Console.WriteLine("New vault file created.");
    }
}
else if (mode == "decrypt")
{
    Console.WriteLine($"Starting decryption: {vaultFolderPath} -> {decryptedFolderPath}");
    if (!File.Exists(vaultFilePath))
    {
        Console.Error.WriteLine($"ERROR: Vault file not found at {vaultFilePath}. Cannot decrypt.");
        return;
    }
    vaultFileContent = File.ReadAllBytes(vaultFilePath);
    Directory.CreateDirectory(decryptedFolderPath); // Ensure decrypted folder exists
}
else
{
    Console.WriteLine("Invalid mode. Use 'encrypt' or 'decrypt'.");
    return;
}

Console.WriteLine("Loading vault...");
using (Vault vault = Vault.LoadUvfVault(vaultFileContent, password))
{
    Console.WriteLine("Vault loaded successfully.");

    // --- Get Root Metadata ---
    // Attempt to load existing root dir.uvf. If it doesn't exist, GetRootDirectoryMetadata()
    // will provide a fresh one (with the correct, persistent RootDirId from the masterkey).
    DirectoryMetadata rootMetadata;
    string rootDirPhysicalPath = Path.Combine(vaultFolderPath, vault.GetRootDirectoryPath());
    string rootDirUvfPath = Path.Combine(rootDirPhysicalPath, "dir.uvf");

    if (mode == "encrypt" && File.Exists(rootDirUvfPath))
    {
        try
        {
            Console.WriteLine($"Loading existing root dir.uvf from: {rootDirUvfPath}");
            byte[] rootDirBytes = File.ReadAllBytes(rootDirUvfPath);
            rootMetadata = vault.DecryptDirectoryMetadata(rootDirBytes);
            Console.WriteLine("Successfully loaded and decrypted existing root metadata.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not load or decrypt existing root dir.uvf ({ex.Message}). Initializing fresh root metadata.");
            rootMetadata = vault.GetRootDirectoryMetadata(); // Fallback to fresh if load fails
        }
    }
    else
    {
        Console.WriteLine("Initializing fresh root metadata (no existing root dir.uvf found or not in encrypt mode).");
        rootMetadata = vault.GetRootDirectoryMetadata();
    }

    if (mode == "encrypt")
    {
        Console.WriteLine($"Encrypting root directory. Source: {sourceFolderPath}, Vault Root Physical Path: {rootDirPhysicalPath}");
        Directory.CreateDirectory(rootDirPhysicalPath); // Ensure physical root content dir exists

        overallStopwatch.Start();
        totalBytesProcessedOverall = ProcessDirectory(vault, sourceFolderPath, rootMetadata, rootDirPhysicalPath);
        overallStopwatch.Stop();
        
        Console.WriteLine("Encryption complete.");
        PrintSpeed("Encrypted", totalBytesProcessedOverall, overallStopwatch.Elapsed);
    }
    else if (mode == "decrypt")
    {
        // For decryption, we MUST have the root dir.uvf
        if (!File.Exists(rootDirUvfPath))
        {
            Console.Error.WriteLine($"ERROR: Root dir.uvf not found at {rootDirUvfPath}. Cannot decrypt.");
            return; // Or handle as appropriate
        }
        try
        {
            Console.WriteLine($"Loading root dir.uvf for decryption from: {rootDirUvfPath}");
            byte[] rootDirBytes = File.ReadAllBytes(rootDirUvfPath);
            rootMetadata = vault.DecryptDirectoryMetadata(rootDirBytes);
             Console.WriteLine("Successfully loaded and decrypted root metadata for decryption.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FATAL: Could not load or decrypt root dir.uvf for decryption ({ex.Message}). Cannot proceed.");
            return;
        }

        Console.WriteLine($"Decrypting root directory. Vault Root Physical Path: {rootDirPhysicalPath}, Target: {decryptedFolderPath}");
        
        overallStopwatch.Start();
        totalBytesProcessedOverall = DecryptDirectory(vault, rootMetadata, rootDirPhysicalPath, decryptedFolderPath);
        overallStopwatch.Stop();

        Console.WriteLine("Decryption complete.");
        PrintSpeed("Decrypted", totalBytesProcessedOverall, overallStopwatch.Elapsed);
    }
}

/// <summary>
/// Recursively processes a source directory, encrypting its contents into the vault.
/// It updates the parent directory's metadata with entries for the items it processes.
/// </summary>
/// <param name="vault">The loaded Vault instance.</param>
/// <param name="sourceDir">The current source directory path to process.</param>
/// <param name="currentDirMetadata">The DirectoryMetadata of the current directory being processed (this will be updated with children).</param>
/// <param name="currentDirPhysicalVaultPath">The full physical path in the vault where this currentDirMetadata's dir.uvf will be stored (e.g., D:\\Vault\\d\\XX\\YYYY).</param>
/// <returns>Total bytes of source files processed in this directory and its subdirectories.</returns>
static long ProcessDirectory(Vault vault, string sourceDir, DirectoryMetadata currentDirMetadata, string currentDirPhysicalVaultPath)
{
    Console.WriteLine($"Processing source directory: {sourceDir} -> mapping to vault path: {currentDirPhysicalVaultPath} (DirId: {currentDirMetadata.DirId})");
    long bytesProcessedInThisCall = 0;

    Directory.CreateDirectory(currentDirPhysicalVaultPath);

    // Process files from the source directory
    foreach (string sourceFilePath in Directory.GetFiles(sourceDir))
    {
        string plainName = Path.GetFileName(sourceFilePath);
        long sourceFileSize = new FileInfo(sourceFilePath).Length;

        string encryptedFilename = vault.EncryptFilename(plainName, currentDirMetadata);
        Console.WriteLine($"  File: {plainName} -> {encryptedFilename}");
        
        string targetEncryptedFilePath = Path.Combine(currentDirPhysicalVaultPath, encryptedFilename);

        bool encryptThisFile = true;
        if (File.Exists(targetEncryptedFilePath))
        {
            long targetFileSize = new FileInfo(targetEncryptedFilePath).Length;
            long expectedEncryptedSize = vault.FileContentCryptor.CiphertextSize(sourceFileSize);
            if (targetFileSize == expectedEncryptedSize)
            {
                Console.WriteLine($"    Skipping (already exists with matching size).");
                bytesProcessedInThisCall += sourceFileSize;
                encryptThisFile = false;
            }
            else
            {
                Console.WriteLine($"    Re-encrypting (size mismatch: disk {targetFileSize} vs expected {expectedEncryptedSize}).");
            }
        }
        else
        {
            Console.WriteLine($"    Encrypting file.");
        }

        if (encryptThisFile)
        {
            try
            {
                using (FileStream sourceStream = File.OpenRead(sourceFilePath))
                using (FileStream targetStream = File.Create(targetEncryptedFilePath))
                using (Stream encryptingStream = vault.GetEncryptingStream(targetStream))
                {
                    sourceStream.CopyTo(encryptingStream);
                }
                bytesProcessedInThisCall += sourceFileSize;
                Console.WriteLine($"      Encrypted successfully.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"    ERROR encrypting file {plainName}: {ex.Message}");
            }
        }
    }

    // Process subdirectories from the source directory
    foreach (string sourceSubDirPath in Directory.GetDirectories(sourceDir))
    {
        string plainSubDirName = Path.GetFileName(sourceSubDirPath);
        Console.WriteLine($"  Subdirectory: {plainSubDirName}");
        
        // Create new metadata for the subdirectory
        DirectoryMetadata subDirMetadata = vault.CreateNewDirectoryMetadata();
        string encryptedSubDirName = vault.EncryptFilename(plainSubDirName, currentDirMetadata);
        
        // Create the encrypted subdirectory name in the parent directory
        string encryptedSubDirPath = Path.Combine(currentDirPhysicalVaultPath, encryptedSubDirName);
        Directory.CreateDirectory(encryptedSubDirPath);
        
        // Write the subdirectory's dir.uvf in the parent directory (for linking)
        byte[] subDirMetadataBytes = vault.EncryptDirectoryMetadata(subDirMetadata);
        string subDirUvfInParent = Path.Combine(encryptedSubDirPath, "dir.uvf");
        File.WriteAllBytes(subDirUvfInParent, subDirMetadataBytes);
        Console.WriteLine($"    Written dir.uvf in parent at: {subDirUvfInParent}");
        
        // Get the actual physical path for the subdirectory content
        string subDirPhysicalVaultPath = Path.Combine(vaultFolderPath, vault.GetDirectoryPath(subDirMetadata));
        Directory.CreateDirectory(subDirPhysicalVaultPath);

        try
        {
            bytesProcessedInThisCall += ProcessDirectory(vault, sourceSubDirPath, subDirMetadata, subDirPhysicalVaultPath);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR processing subdirectory {plainSubDirName}: {ex.Message}");
        }
    }

    // Write the current directory's dir.uvf file (in its own directory)
    try
    {
        byte[] encryptedMetadataBytes = vault.EncryptDirectoryMetadata(currentDirMetadata);
        string dirUvfPath = Path.Combine(currentDirPhysicalVaultPath, "dir.uvf");
        File.WriteAllBytes(dirUvfPath, encryptedMetadataBytes);
        Console.WriteLine($"  Written dir.uvf for: {currentDirPhysicalVaultPath} (DirId: {currentDirMetadata.DirId})");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"  ERROR writing dir.uvf for {currentDirPhysicalVaultPath}: {ex.Message}");
    }
    return bytesProcessedInThisCall;
}

/// <summary>
/// Recursively decrypts a vault directory into the target decrypted folder.
/// </summary>
/// <param name="vault">The loaded Vault instance.</param>
/// <param name="currentDirectoryMetadata">The (already decrypted) DirectoryMetadata for the current directory being processed. This contains the list of children.</param>
/// <param name="currentDirPhysicalVaultPath">The full physical path in the vault from which this currentDirectoryMetadata was loaded (e.g., D:\Vault\d\XX\YYYY).</param>
/// <param name="targetDecryptedPath">The path on the local filesystem where the decrypted contents should be written.</param>
static long DecryptDirectory(Vault vault, DirectoryMetadata currentDirectoryMetadata, string currentDirPhysicalVaultPath, string targetDecryptedPath)
{
    Console.WriteLine($"Decrypting directory from: {currentDirPhysicalVaultPath} -> to: {targetDecryptedPath}");
    
    Directory.CreateDirectory(targetDecryptedPath); // Ensure target directory exists

    long bytesProcessedInThisCall = 0;

    // List all items in the physical directory
    foreach (string encryptedPath in Directory.GetFileSystemEntries(currentDirPhysicalVaultPath))
    {
        string encryptedName = Path.GetFileName(encryptedPath);
        
        // Skip the dir.uvf file itself
        if (encryptedName == "dir.uvf")
            continue;
            
        try
        {
            // Check if it's a directory (contains dir.uvf)
            if (Directory.Exists(encryptedPath))
            {
                string dirUvfPath = Path.Combine(encryptedPath, "dir.uvf");
                if (File.Exists(dirUvfPath))
                {
                    // It's a subdirectory
                    string decryptedName = vault.DecryptFilename(encryptedName, currentDirectoryMetadata);
                    Console.WriteLine($"  Found subdirectory: {encryptedName} -> {decryptedName}");
                    
                    // Read the subdirectory's metadata from the parent directory
                    byte[] dirUvfBytes = File.ReadAllBytes(dirUvfPath);
                    DirectoryMetadata subDirMetadata = vault.DecryptDirectoryMetadata(dirUvfBytes);
                    
                    // Get the subdirectory's actual physical path
                    string subDirPhysicalPath = Path.Combine(vaultFolderPath, vault.GetDirectoryPath(subDirMetadata));
                    string targetSubDirPath = Path.Combine(targetDecryptedPath, decryptedName);
                    
                    // Recursively decrypt the subdirectory
                    bytesProcessedInThisCall += DecryptDirectory(vault, subDirMetadata, subDirPhysicalPath, targetSubDirPath);
                }
                else
                {
                    Console.WriteLine($"  WARNING: Directory {encryptedName} has no dir.uvf file. Skipping.");
                }
            }
            else if (File.Exists(encryptedPath))
            {
                // It's a file
                string decryptedName = vault.DecryptFilename(encryptedName, currentDirectoryMetadata);
                Console.WriteLine($"  Found file: {encryptedName} -> {decryptedName}");
                
                string targetFilePath = Path.Combine(targetDecryptedPath, decryptedName);
                
                using (FileStream encryptedStream = File.OpenRead(encryptedPath))
                using (FileStream decryptedStream = File.Create(targetFilePath))
                using (Stream decryptingStream = vault.GetDecryptingStream(encryptedStream))
                {
                    decryptingStream.CopyTo(decryptedStream);
                }
                Console.WriteLine($"    Decrypted file: {targetFilePath}");
                bytesProcessedInThisCall += new FileInfo(encryptedPath).Length;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR processing item '{encryptedName}': {ex.Message}");
        }
    }
    return bytesProcessedInThisCall;
}

// Make sure to add GetMasterkey() and GetRootDirIdString() to Vault and UVFMasterkey interface/impl if they don't exist.
// Also AddChildToDirectoryMetadata, ClearChildrenInDirectoryMetadata, SetChildrenForDirectoryMetadata to Vault and underlying DirectoryContentCryptor/DirectoryMetadataImpl
// And vault.GetDirectoryPathByDirId(string dirId)

static void PrintSpeed(string operationLabel, long totalBytes, TimeSpan elapsed)
{
    Console.WriteLine($"{operationLabel} {totalBytes} bytes.");
    if (elapsed.TotalSeconds > 0 && totalBytes > 0)
    {
        double megabytes = totalBytes / (1024.0 * 1024.0);
        double speed = megabytes / elapsed.TotalSeconds;
        Console.WriteLine($"Speed: {speed:F2} MB/s ({elapsed.TotalMilliseconds:F0} ms)");
    }
    else if (totalBytes == 0)
    {
        Console.WriteLine("No data processed to calculate speed.");
    }
    else
    {
         Console.WriteLine($"Time elapsed: {elapsed.TotalMilliseconds:F0} ms (too fast to calculate meaningful speed for small data or speed calculation not applicable).");
    }
} 