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
            // For root directory, we need to get its DirId from the metadata itself
            DirectoryMetadata tempRootMetadata = vault.GetRootDirectoryMetadata();
            rootMetadata = vault.DecryptDirectoryMetadata(rootDirBytes, tempRootMetadata.DirId);
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
            // For root directory, we need to get its DirId from the metadata itself
            DirectoryMetadata tempRootMetadata = vault.GetRootDirectoryMetadata();
            rootMetadata = vault.DecryptDirectoryMetadata(rootDirBytes, tempRootMetadata.DirId);
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

    // Create a list of child names from the source directory to track what's currently present
    var sourceChildrenNames = new HashSet<string>(Directory.GetFiles(sourceDir).Select(Path.GetFileName));
    sourceChildrenNames.UnionWith(Directory.GetDirectories(sourceDir).Select(Path.GetFileName));

    // Create a list of children to keep/update in the metadata
    var newChildrenMetadataList = new List<VaultChildItem>();

    // 1. Process existing items in metadata: update them or mark for removal if not in source
    if (currentDirMetadata.Children != null)
    {
        foreach (VaultChildItem existingChildItem in currentDirMetadata.Children)
        {
            string decryptedExistingChildName = "";
            try
            {
                decryptedExistingChildName = vault.DecryptFilename(existingChildItem.EncryptedName, currentDirMetadata);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"    WARNING: Could not decrypt existing metadata entry '{existingChildItem.EncryptedName}' in dirId {currentDirMetadata.DirId}. Skipping. Error: {ex.Message}");
                continue; // Skip this problematic entry
            }

            string sourcePathForExistingChild = Path.Combine(sourceDir, decryptedExistingChildName);

            if (!sourceChildrenNames.Contains(decryptedExistingChildName))
            {
                Console.WriteLine($"  Item '{decryptedExistingChildName}' (encrypted: {existingChildItem.EncryptedName}) no longer in source. Will be removed from metadata.");
                // Do nothing here; it won't be added to newChildrenMetadataList
                // Actual deletion of orphaned encrypted files/dirs is a separate, more complex task.
            }
            else
            {
                // Item exists in source, process it (it will be re-added to newChildrenMetadataList later if it's a file or recursively processed if a dir)
                // For now, we just acknowledge it's still in source. The loops below will handle its processing.
                // Remove from sourceChildrenNames so we know what's left are new items.
                sourceChildrenNames.Remove(decryptedExistingChildName);
            }
        }
    }
    // Now sourceChildrenNames contains only items that are new in the sourceDir (or were not in old metadata)

    // 2. Process files from the source directory
    foreach (string sourceFilePath in Directory.GetFiles(sourceDir))
    {
        string plainName = Path.GetFileName(sourceFilePath);
        long sourceFileSize = new FileInfo(sourceFilePath).Length;
        VaultChildItem? existingFileMetadata = currentDirMetadata.Children?.FirstOrDefault(c => c.Type == VaultChildItem.ItemType.File && vault.DecryptFilename(c.EncryptedName, currentDirMetadata) == plainName);

        string encryptedFilename;
        if (existingFileMetadata != null)
        {
            encryptedFilename = existingFileMetadata.EncryptedName;
            Console.WriteLine($"  File (update check): {plainName} (existing encrypted: {encryptedFilename})");
        }
        else
        {
            encryptedFilename = vault.EncryptFilename(plainName, currentDirMetadata);
            Console.WriteLine($"  File (new): {plainName} -> {encryptedFilename}");
        }
        
        string targetEncryptedFilePath = Path.Combine(currentDirPhysicalVaultPath, encryptedFilename);

        bool encryptThisFile = true;
        if (File.Exists(targetEncryptedFilePath) && existingFileMetadata != null) // Only skip if it was known in metadata
        {
            long targetFileSize = new FileInfo(targetEncryptedFilePath).Length;
            long expectedEncryptedSize = vault.FileContentCryptor.CiphertextSize(sourceFileSize);
            if (targetFileSize == expectedEncryptedSize)
            {
                Console.WriteLine($"    Skipping (already exists with matching size).");
                bytesProcessedInThisCall += sourceFileSize;
                encryptThisFile = false;
                newChildrenMetadataList.Add(existingFileMetadata); // Keep existing metadata entry
            }
            else
            {
                Console.WriteLine($"    Re-encrypting (size mismatch: disk {targetFileSize} vs expected {expectedEncryptedSize}).");
            }
        }
        else if (existingFileMetadata == null) // New file
        {
             Console.WriteLine($"    Encrypting (new file).");
        }
        else // Known in metadata, but encrypted file not on disk (should re-encrypt)
        {
            Console.WriteLine($"    Encrypting (file was in metadata but not found on disk at {targetEncryptedFilePath}).");
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

                var fileChildItem = new VaultChildItem
                {
                    EncryptedName = encryptedFilename,
                    Type = VaultChildItem.ItemType.File,
                    DirId = null
                };
                newChildrenMetadataList.Add(fileChildItem);
                Console.WriteLine($"      Processed and added/updated file entry: {encryptedFilename}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"    ERROR encrypting file {plainName}: {ex.Message}");
            }
        }
    }

    // 3. Process subdirectories from the source directory
    foreach (string sourceSubDirPath in Directory.GetDirectories(sourceDir))
    {
        string plainSubDirName = Path.GetFileName(sourceSubDirPath);
        VaultChildItem? existingDirMetadataChildInfo = currentDirMetadata.Children?.FirstOrDefault(c => c.Type == VaultChildItem.ItemType.Directory && vault.DecryptFilename(c.EncryptedName, currentDirMetadata) == plainSubDirName);
        DirectoryMetadata subDirMetadata;
        string subDirPhysicalVaultPath;
        string encryptedSubDirName;

        if (existingDirMetadataChildInfo != null && !string.IsNullOrEmpty(existingDirMetadataChildInfo.DirId))
        {
            Console.WriteLine($"  Subdirectory (update check): {plainSubDirName} (existing DirId: {existingDirMetadataChildInfo.DirId})");
            encryptedSubDirName = existingDirMetadataChildInfo.EncryptedName; // Use existing encrypted name
            subDirPhysicalVaultPath = Path.Combine(vaultFolderPath, vault.GetDirectoryPathByDirId(existingDirMetadataChildInfo.DirId));
            string subDirUvfPath = Path.Combine(subDirPhysicalVaultPath, "dir.uvf");
            if (File.Exists(subDirUvfPath))
            {
                try
                {
                    byte[] subDirBytes = File.ReadAllBytes(subDirUvfPath);
                    subDirMetadata = vault.DecryptDirectoryMetadata(subDirBytes, existingDirMetadataChildInfo.DirId);
                    Console.WriteLine($"    Loaded existing metadata for subdir: {plainSubDirName}");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"    ERROR loading existing dir.uvf for {plainSubDirName} (DirId: {existingDirMetadataChildInfo.DirId}). Error: {ex.Message}");
                    Console.WriteLine($"    Preserving existing entry without processing subdirectory.");
                    
                    // Keep the existing entry to preserve it
                    newChildrenMetadataList.Add(existingDirMetadataChildInfo);
                    Console.WriteLine($"      Preserved existing directory entry: {existingDirMetadataChildInfo.EncryptedName} (DirId: {existingDirMetadataChildInfo.DirId})");
                    
                    // Skip processing this subdirectory
                    continue;
                }
            }
            else
            {
                Console.WriteLine($"    dir.uvf not found for existing subdir entry {plainSubDirName} (DirId: {existingDirMetadataChildInfo.DirId}). Preserving existing entry.");
                // The dir.uvf is missing but we have the DirId from parent metadata
                // Creating new metadata would cause a mismatch, so we'll preserve the existing entry
                // and skip processing this subdirectory
                
                // Keep the existing encrypted name and DirId
                encryptedSubDirName = existingDirMetadataChildInfo.EncryptedName;
                
                // Add the existing entry to the new children list to preserve it
                newChildrenMetadataList.Add(existingDirMetadataChildInfo);
                Console.WriteLine($"      Preserved existing directory entry: {encryptedSubDirName} (DirId: {existingDirMetadataChildInfo.DirId})");
                
                // Skip processing this subdirectory since we can't create proper metadata for it
                continue;
            }
        }
        else // New subdirectory
        {
            Console.WriteLine($"  Subdirectory (new): {plainSubDirName}");
            subDirMetadata = vault.CreateNewDirectoryMetadata();
            encryptedSubDirName = vault.EncryptFilename(plainSubDirName, currentDirMetadata);
            subDirPhysicalVaultPath = Path.Combine(vaultFolderPath, vault.GetDirectoryPath(subDirMetadata));
        }
        
        Directory.CreateDirectory(subDirPhysicalVaultPath); // Ensure physical dir exists before recursive call / writing its dir.uvf

        try
        {
            bytesProcessedInThisCall += ProcessDirectory(vault, sourceSubDirPath, subDirMetadata, subDirPhysicalVaultPath);
            
            // Add/update this subdirectory in the new children list for the current directory
            var dirChildItem = new VaultChildItem
            {
                EncryptedName = encryptedSubDirName, // Name encrypted with currentDirMetadata's context
                Type = VaultChildItem.ItemType.Directory,
                DirId = subDirMetadata.DirId // The DirId of the subdirectory itself
            };
            newChildrenMetadataList.Add(dirChildItem);
            Console.WriteLine($"      Processed and added/updated directory entry: {encryptedSubDirName} (DirId: {subDirMetadata.DirId})");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR processing subdirectory {plainSubDirName}: {ex.Message}");
        }
    }

    // Update currentDirMetadata with the new list of children
    vault.ClearChildrenInDirectoryMetadata(currentDirMetadata);
    foreach (var child in newChildrenMetadataList)
    {
        vault.AddChildToDirectoryMetadata(currentDirMetadata, child);
    }

    // Write the (potentially updated) currentDirMetadata to its dir.uvf file
    try
    {
        byte[] encryptedMetadataBytes = vault.EncryptDirectoryMetadata(currentDirMetadata);
        string dirUvfPath = Path.Combine(currentDirPhysicalVaultPath, "dir.uvf");
        File.WriteAllBytes(dirUvfPath, encryptedMetadataBytes);
        Console.WriteLine($"  Written dir.uvf for: {currentDirPhysicalVaultPath} (DirId: {currentDirMetadata.DirId}, Children: {currentDirMetadata.Children?.Count ?? 0})");
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
    Console.WriteLine($"Decrypting items listed in metadata for physical vault path: {currentDirPhysicalVaultPath} -> to target: {targetDecryptedPath}");
    
    Directory.CreateDirectory(targetDecryptedPath); // Ensure target directory exists

    if (currentDirectoryMetadata.Children == null || !currentDirectoryMetadata.Children.Any())
    {
        Console.WriteLine("  No children listed in metadata. Directory is empty or only contains dir.uvf.");
        return 0;
    }

    long bytesProcessedInThisCall = 0;

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
                bytesProcessedInThisCall += DecryptDirectory(vault, childMetadata, childEncryptedPhysicalPath, targetFullPath);
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
                bytesProcessedInThisCall += new FileInfo(encryptedFileSourcePath).Length;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"    ERROR processing item '{childItem.EncryptedName}' (decrypted name attempt: '{decryptedName}'): {ex.Message}");
            // Optionally, continue to the next item rather than stopping all decryption
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