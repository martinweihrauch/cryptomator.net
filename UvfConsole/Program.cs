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

    DirectoryMetadata rootMetadata = vault.GetRootDirectoryMetadata();
    string rootDirPhysicalPath = Path.Combine(vaultFolderPath, vault.GetDirectoryPath(rootMetadata));

    if (mode == "encrypt")
    {
        Console.WriteLine($"Encrypting root directory. Source: {sourceFolderPath}, Vault Root Physical Path: {rootDirPhysicalPath}");
        // Ensure the physical root directory for the vault exists (e.g., d/XX/YYYY for root dirID)
        Directory.CreateDirectory(rootDirPhysicalPath);
        ProcessDirectory(vault, sourceFolderPath, rootMetadata, rootDirPhysicalPath);
        Console.WriteLine("Encryption complete.");
    }
    else if (mode == "decrypt")
    {
        Console.WriteLine($"Decrypting root directory. Vault Root Physical Path: {rootDirPhysicalPath}, Target: {decryptedFolderPath}");
        DecryptDirectory(vault, rootMetadata, rootDirPhysicalPath, decryptedFolderPath);
        Console.WriteLine("Decryption complete.");
    }
}

/// <summary>
/// Recursively processes a source directory, encrypting its contents into the vault.
/// It updates the parent directory's metadata with entries for the items it processes.
/// </summary>
/// <param name="vault">The loaded Vault instance.</param>
/// <param name="sourceDir">The current source directory path to process.</param>
/// <param name="currentDirMetadata">The DirectoryMetadata of the current directory being processed (this will be updated with children).</param>
/// <param name="currentDirPhysicalVaultPath">The full physical path in the vault where this currentDirMetadata's dir.uvf will be stored (e.g., D:\Vault\d\XX\YYYY).</param>
static void ProcessDirectory(Vault vault, string sourceDir, DirectoryMetadata currentDirMetadata, string currentDirPhysicalVaultPath)
{
    Console.WriteLine($"Processing source directory: {sourceDir} -> to be listed in: {currentDirPhysicalVaultPath}");

    // Ensure the physical directory for the current metadata exists (it might be the root or a newly created one)
    Directory.CreateDirectory(currentDirPhysicalVaultPath);

    // Clear any existing children from the current directory's metadata, as we are rebuilding its content based on sourceDir.
    // This handles cases where files/subdirs might have been deleted from sourceDir since last encryption.
    vault.ClearChildrenInDirectoryMetadata(currentDirMetadata);

    // Process files in the current source directory
    foreach (string sourceFilePath in Directory.GetFiles(sourceDir))
    {
        string plainName = Path.GetFileName(sourceFilePath);
        Console.WriteLine($"  Encrypting file: {plainName}");

        try
        {
            string encryptedFilename = vault.EncryptFilename(plainName, currentDirMetadata);
            string targetEncryptedFilePath = Path.Combine(currentDirPhysicalVaultPath, encryptedFilename);

            using (FileStream sourceStream = File.OpenRead(sourceFilePath))
            using (FileStream targetStream = File.Create(targetEncryptedFilePath))
            // Use the SeedId from the current directory's metadata for its direct file children
            using (Stream encryptingStream = vault.GetEncryptingStream(targetStream, currentDirMetadata.SeedId))
            {
                sourceStream.CopyTo(encryptingStream);
            }

            // Add this file as a child to the current directory's metadata
            var fileChildItem = new VaultChildItem
            {
                EncryptedName = encryptedFilename,
                Type = VaultChildItem.ItemType.File,
                DirId = null // Files don't have a DirId in this context
            };
            vault.AddChildToDirectoryMetadata(currentDirMetadata, fileChildItem);
            Console.WriteLine($"    Added file entry to metadata: {encryptedFilename}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR encrypting file {plainName}: {ex.Message}");
        }
    }

    // Process subdirectories in the current source directory
    foreach (string sourceSubDir in Directory.GetDirectories(sourceDir))
    {
        string plainSubDirName = Path.GetFileName(sourceSubDir);
        Console.WriteLine($"  Processing subdirectory: {plainSubDirName}");

        try
        {
            // 1. Create metadata for the new subdirectory. This generates its unique DirId and determines its SeedId.
            DirectoryMetadata subDirMetadata = vault.CreateNewDirectoryMetadata();

            // 2. Determine the physical path for this new subdirectory's content based on its DirId.
            string encryptedSubDirPhysicalPath = Path.Combine(vaultFolderPath, vault.GetDirectoryPath(subDirMetadata));
            // Directory.CreateDirectory(encryptedSubDirPhysicalPath); // This will be created by the recursive call or just before writing dir.uvf

            // 3. Recursively process the subdirectory.
            // This call will populate subDirMetadata.Children and write its dir.uvf file.
            ProcessDirectory(vault, sourceSubDir, subDirMetadata, encryptedSubDirPhysicalPath);

            // 4. After the recursive call, add this subdirectory as a child to the *current* directory's metadata.
            // The name is encrypted using the *current* directory's context.
            string encryptedSubDirName = vault.EncryptFilename(plainSubDirName, currentDirMetadata);
            var dirChildItem = new VaultChildItem
            {
                EncryptedName = encryptedSubDirName,
                Type = VaultChildItem.ItemType.Directory,
                DirId = subDirMetadata.DirId // Store the Base64Url DirId of the child directory
            };
            vault.AddChildToDirectoryMetadata(currentDirMetadata, dirChildItem);
            Console.WriteLine($"    Added directory entry to metadata: {encryptedSubDirName} (DirId: {subDirMetadata.DirId})");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR processing subdirectory {plainSubDirName}: {ex.Message}");
        }
    }

    // After processing all files and subdirectories for sourceDir,
    // write the (now populated) currentDirMetadata to its dir.uvf file.
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
}

/// <summary>
/// Recursively decrypts a vault directory into the target decrypted folder.
/// </summary>
/// <param name="vault">The loaded Vault instance.</param>
/// <param name="currentDirectoryMetadata">The (already decrypted) DirectoryMetadata for the current directory being processed. This contains the list of children.</param>
/// <param name="currentDirPhysicalVaultPath">The full physical path in the vault from which this currentDirectoryMetadata was loaded (e.g., D:\Vault\d\XX\YYYY).</param>
/// <param name="targetDecryptedPath">The path on the local filesystem where the decrypted contents should be written.</param>
static void DecryptDirectory(Vault vault, DirectoryMetadata currentDirectoryMetadata, string currentDirPhysicalVaultPath, string targetDecryptedPath)
{
    Console.WriteLine($"Decrypting items listed in metadata for physical vault path: {currentDirPhysicalVaultPath} -> to target: {targetDecryptedPath}");
    
    Directory.CreateDirectory(targetDecryptedPath); // Ensure target directory exists

    if (currentDirectoryMetadata.Children == null || !currentDirectoryMetadata.Children.Any())
    {
        Console.WriteLine("  No children listed in metadata. Directory is empty or only contains dir.uvf.");
        return;
    }

    foreach (VaultChildItem childItem in currentDirectoryMetadata.Children)
    {
        string decryptedName = ""; // Initialize to prevent compiler error on finally path
        try
        {
            // Decrypt the name using the metadata of the current directory we are in.
            decryptedName = vault.DecryptFilename(childItem.EncryptedName, currentDirectoryMetadata);
            string targetFullPath = Path.Combine(targetDecryptedPath, decryptedName);

            if (childItem.Type == VaultChildItem.ItemType.Directory)
            {
                Console.WriteLine($"  Found directory listing: {childItem.EncryptedName} -> decrypted as: {decryptedName}");
                if (string.IsNullOrEmpty(childItem.DirId))
                {
                    Console.Error.WriteLine($"    ERROR: Directory item '{childItem.EncryptedName}' is missing DirId in metadata. Skipping.");
                    continue;
                }

                // 1. Get the child directory's physical path using its DirId.
                string childEncryptedPhysicalPath = Path.Combine(vaultFolderPath, vault.GetDirectoryPathByDirId(childItem.DirId));
                string childDirUvfPath = Path.Combine(childEncryptedPhysicalPath, "dir.uvf");

                if (!File.Exists(childDirUvfPath))
                {
                    Console.Error.WriteLine($"    ERROR: dir.uvf not found for child directory '{decryptedName}' at expected path '{childDirUvfPath}'. Skipping.");
                    continue;
                }

                // 2. Read and decrypt its dir.uvf to get its metadata.
                // The DirId of the child directory itself is used as AAD for decrypting its dir.uvf.
                byte[] childEncMetaBytes = File.ReadAllBytes(childDirUvfPath);
                DirectoryMetadata childMetadata = vault.DecryptDirectoryMetadata(childEncMetaBytes, childItem.DirId);
                
                // 3. Recursively call DecryptDirectory for the subdirectory.
                DecryptDirectory(vault, childMetadata, childEncryptedPhysicalPath, targetFullPath);
            }
            else // It's a file
            {
                Console.WriteLine($"  Found file listing: {childItem.EncryptedName} -> decrypted as: {decryptedName}");
                string encryptedFileSourcePath = Path.Combine(currentDirPhysicalVaultPath, childItem.EncryptedName);
                
                if (!File.Exists(encryptedFileSourcePath))
                {
                    Console.Error.WriteLine($"    ERROR: Encrypted file '{childItem.EncryptedName}' not found at physical path '{encryptedFileSourcePath}'. Listed in parent dir.uvf but missing. Skipping.");
                    continue;
                }

                using (FileStream encryptedStream = File.OpenRead(encryptedFileSourcePath))
                using (FileStream decryptedStream = File.Create(targetFullPath))
                using (Stream decryptingStream = vault.GetDecryptingStream(encryptedStream))
                {
                    decryptingStream.CopyTo(decryptedStream);
                }
                Console.WriteLine($"    Decrypted file: {targetFullPath}");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR processing item '{childItem.EncryptedName}' (decrypted name attempt: '{decryptedName}'): {ex.Message}");
            // Optionally, continue to the next item rather than stopping all decryption
        }
    }
} 