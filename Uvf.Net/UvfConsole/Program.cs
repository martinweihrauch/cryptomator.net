using UvfLib; // Assuming Vault class is in this namespace
using UvfLib.Api; // For DirectoryMetadata and exceptions
using System.Diagnostics; // For Stopwatch

Console.WriteLine("UvfLib Simple Encryption Example");

// --- Configuration --- 
// IMPORTANT: Replace with your actual paths!
const string sourceFolderPath = @"D:\\temp\\uvf\\EncryptionTestSource"; // Folder containing files/dirs to encrypt
const string vaultFolderPath = @"D:\\temp\\uvf\\EncryptionTestVault";   // Target folder where encrypted vault structure will be created
const string decryptedFolderPath = @"D:\\temp\\uvf\\EncryptionTestDecrypted"; // Target folder for decrypted content
const string password = "your-super-secret-password";
// ---------------------

// Parse command-line arguments
string operation = args.Length > 0 ? args[0].ToLower() : "";

if (operation != "encrypt" && operation != "decrypt")
{
    Console.WriteLine("Usage: UvfConsole [encrypt|decrypt]");
    Console.WriteLine("  encrypt - Encrypt files from sourceFolderPath to vaultFolderPath (default)");
    Console.WriteLine("  decrypt - Decrypt files from vaultFolderPath to decryptedFolderPath");
    return;
}

// Ensure target directories exist
Directory.CreateDirectory(vaultFolderPath);
if (operation == "decrypt")
{
    Directory.CreateDirectory(decryptedFolderPath);
}

string masterkeyFilePath = Path.Combine(vaultFolderPath, "vault.uvf");

try
{
    // --- Vault Setup ---
    byte[] masterkeyContent;
    if (!File.Exists(masterkeyFilePath))
    {
        if (operation == "decrypt")
        {
            Console.Error.WriteLine($"ERROR: Masterkey file not found at {masterkeyFilePath}. Cannot decrypt.");
            return;
        }
        
        Console.WriteLine($"Masterkey file not found. Creating new one at: {masterkeyFilePath}");
        masterkeyContent = Vault.CreateNewUvfVaultFileContent(password);
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
    using (Vault vault = Vault.LoadUvfVault(masterkeyContent, password))
    {
        Console.WriteLine("Vault loaded successfully.");

        if (operation == "encrypt")
        {
            // --- Recursive Encryption ---
            Console.WriteLine($"Starting encryption from '{sourceFolderPath}' to '{vaultFolderPath}'...");
            
            Stopwatch encryptionStopwatch = Stopwatch.StartNew();
            long totalBytesProcessed = 0;

            // Get root metadata and the physical path for the encrypted root content
            DirectoryMetadata rootMetadata = vault.GetRootDirectoryMetadata();
            string vaultRootContentPath = vault.GetRootDirectoryPath(); // Path like "d/XX/YYYY..."
            string fullVaultRootContentPath = Path.Combine(vaultFolderPath, vaultRootContentPath);
            Directory.CreateDirectory(fullVaultRootContentPath); // Ensure physical root content dir exists

            // Start recursive processing
            totalBytesProcessed = ProcessDirectory(vault, sourceFolderPath, fullVaultRootContentPath, rootMetadata);

            encryptionStopwatch.Stop();
            Console.WriteLine("Encryption process completed.");
            PrintSpeed("Encrypted", totalBytesProcessed, encryptionStopwatch.Elapsed);
        }
        else // decrypt
        {
            Console.WriteLine($"Starting decryption from '{vaultFolderPath}' to '{decryptedFolderPath}'...");
            Stopwatch decryptionStopwatch = Stopwatch.StartNew();
            long totalBytesProcessed = 0;
            
            // Get root metadata and start decryption from the root
            DirectoryMetadata rootMetadata = vault.GetRootDirectoryMetadata();
            string vaultRootContentPath = vault.GetRootDirectoryPath();
            string fullVaultRootContentPath = Path.Combine(vaultFolderPath, vaultRootContentPath);
            
            // Start recursive decryption
            totalBytesProcessed = DecryptDirectory(vault, fullVaultRootContentPath, decryptedFolderPath, rootMetadata);
            
            decryptionStopwatch.Stop();
            Console.WriteLine("Decryption process completed.");
            PrintSpeed("Decrypted", totalBytesProcessed, decryptionStopwatch.Elapsed);
        }
    }
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
/// <returns>Total bytes of source files processed.</returns>
static long ProcessDirectory(Vault vault, string sourceDir, string targetEncryptedPath, DirectoryMetadata parentDirMetadata)
{
    Console.WriteLine($"Processing directory: {sourceDir}");
    long currentDirBytesProcessed = 0;

    // --- Encrypt Files in Current Directory ---
    foreach (string sourceFile in Directory.GetFiles(sourceDir))
    {
        string plainName = Path.GetFileName(sourceFile);
        long sourceFileSize = 0;
        try
        {
            sourceFileSize = new FileInfo(sourceFile).Length;
            // Encrypt filename using parent directory's metadata
            string encryptedFilename = vault.EncryptFilename(plainName, parentDirMetadata);
            string targetFilePath = Path.Combine(targetEncryptedPath, encryptedFilename);

            // Check if file already exists
            if (File.Exists(targetFilePath))
            {
                // Get the target file size
                long targetFileSize = new FileInfo(targetFilePath).Length;
                
                // Calculate expected encrypted size (header + content size rounded to chunks)
                long expectedEncryptedSize = vault.FileContentCryptor.CiphertextSize(sourceFileSize);
                
                // If sizes match, skip the file
                if (targetFileSize == expectedEncryptedSize)
                {
                    Console.WriteLine($"  Skipping file (already exists with matching size): {plainName}");
                    currentDirBytesProcessed += sourceFileSize; // Count skipped files as processed for throughput
                    continue;
                }
                else
                {
                    Console.WriteLine($"  Re-encrypting file (size changed): {plainName}");
                }
            }
            else
            {
                Console.WriteLine($"  Encrypting file: {plainName}");
            }

            // Encrypt content using streams
            using FileStream sourceStream = File.OpenRead(sourceFile);
            using FileStream targetStream = File.Create(targetFilePath);
            using Stream encryptingStream = vault.GetEncryptingStream(targetStream);

            sourceStream.CopyTo(encryptingStream); 
            currentDirBytesProcessed += sourceFileSize; // Add after successful processing or decision to process
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR encrypting file {plainName}: {ex.Message}");
            // Optionally, still add sourceFileSize if you want to count attempted bytes:
            // currentDirBytesProcessed += sourceFileSize; 
        }
    }

    // --- Process Subdirectories --- 
    foreach (string sourceSubDir in Directory.GetDirectories(sourceDir))
    {
        string plainSubDirName = Path.GetFileName(sourceSubDir);
        Console.WriteLine($"  Processing subdirectory: {plainSubDirName}");
        try
        {
            // 1. Create metadata for the new directory - Revert to UvfLib.Api.DirectoryMetadata interface
            UvfLib.Api.DirectoryMetadata subDirMetadata = vault.CreateNewDirectoryMetadata();

            // 2. Get the *actual encrypted path* for this new directory's content using its OWN metadata
            string encryptedSubDirPath = vault.GetDirectoryPath(subDirMetadata); // Path like d/YY/ZZZZ...
            string fullTargetSubDirPath = Path.Combine(vaultFolderPath, encryptedSubDirPath);

            // Check if this directory structure already exists with a dir.uvf file
            string dirUvfPath = Path.Combine(fullTargetSubDirPath, "dir.uvf");
            bool dirExists = Directory.Exists(fullTargetSubDirPath) && File.Exists(dirUvfPath);
            
            if (!dirExists)
            {
                // 3. Create the physical directory for the encrypted content
                Directory.CreateDirectory(fullTargetSubDirPath);

                // 4. Encrypt the new directory's metadata 
                byte[] encryptedMetadataBytes = vault.EncryptDirectoryMetadata(subDirMetadata);

                // 5. Write the dir.uvf file inside the encrypted directory path
                File.WriteAllBytes(dirUvfPath, encryptedMetadataBytes);
                Console.WriteLine($"    Created encrypted directory structure at: {fullTargetSubDirPath}");
            }
            else
            {
                Console.WriteLine($"    Reusing existing directory structure at: {fullTargetSubDirPath}");
                byte[] encryptedMetadataBytes = File.ReadAllBytes(dirUvfPath);
                subDirMetadata = vault.DecryptDirectoryMetadata(encryptedMetadataBytes, subDirMetadata.DirId); 
            }

            // 6. Recursively process the subdirectory
            currentDirBytesProcessed += ProcessDirectory(vault, sourceSubDir, fullTargetSubDirPath, subDirMetadata);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR processing subdirectory {plainSubDirName}: {ex.Message}");
        }
    }
    return currentDirBytesProcessed;
}

/// <summary>
/// Recursively decrypts a vault directory into the target decrypted folder.
/// </summary>
/// <param name="vault">The loaded Vault instance.</param>
/// <param name="encryptedDirPath">The encrypted directory path to decrypt.</param>
/// <param name="targetDecryptedPath">The target path for decrypted content.</param>
/// <param name="directoryMetadata">The DirectoryMetadata for the current directory.</param>
/// <returns>Total bytes of decrypted files.</returns>
static long DecryptDirectory(Vault vault, string encryptedDirPath, string targetDecryptedPath, DirectoryMetadata directoryMetadata)
{
    Console.WriteLine($"Decrypting directory: {encryptedDirPath}");
    long currentDirBytesDecrypted = 0;
    
    // Ensure target directory exists
    Directory.CreateDirectory(targetDecryptedPath);

    // Process all encrypted files in this directory
    var files = Directory.GetFiles(encryptedDirPath);
    foreach (string encryptedFile in files)
    {
        string encryptedFileName = Path.GetFileName(encryptedFile);
        
        if (encryptedFileName == "dir.uvf") 
            continue;
        
        try
        {
            string decryptedFileName = vault.DecryptFilename(encryptedFileName, directoryMetadata);
            string targetFilePath = Path.Combine(targetDecryptedPath, decryptedFileName);
            
            Console.WriteLine($"  Decrypting file: {encryptedFileName} -> {decryptedFileName}");
            
            using (FileStream encryptedStream = File.OpenRead(encryptedFile))
            using (FileStream decryptedStream = File.Create(targetFilePath))
            using (Stream decryptingStream = vault.GetDecryptingStream(encryptedStream))
            {
                decryptingStream.CopyTo(decryptedStream);
            }
            currentDirBytesDecrypted += new FileInfo(targetFilePath).Length; // Add size of successfully decrypted file
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR decrypting file {encryptedFileName}: {ex.Message}");
        }
    }
    
    foreach (string potentialSubDir in Directory.GetDirectories(encryptedDirPath))
    {
        try
        {
            string dirUvfPath = Path.Combine(potentialSubDir, "dir.uvf");
            if (!File.Exists(dirUvfPath))
            {
                Console.WriteLine($"  Skipping directory without metadata: {potentialSubDir}");
                continue;
            }
            
            byte[] encryptedMetadataBytes = File.ReadAllBytes(dirUvfPath);
            DirectoryMetadata subDirMetadata = vault.DecryptDirectoryMetadata(encryptedMetadataBytes, "TODO_NEEDS_ACTUAL_DIR_ID_FOR_THIS_PATH"); 
            
            string subDirName = $"Folder_{Path.GetFileName(potentialSubDir)}";
            string targetSubDirPath = Path.Combine(targetDecryptedPath, subDirName);
            
            currentDirBytesDecrypted += DecryptDirectory(vault, potentialSubDir, targetSubDirPath, subDirMetadata);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR processing subdirectory {potentialSubDir}: {ex.Message}");
        }
    }
    return currentDirBytesDecrypted;
}

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
