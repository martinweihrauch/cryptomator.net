using UvfLib;
using UvfLib.Api;
using UvfLib.V3;
using UvfLib.VaultHelpers;
using System.Diagnostics;
using System.Linq;

namespace UvfConsole
{
    public class Program
    {
        // Configuration
        private const string SourceFolderPath = @"D:\temp\uvf\EncryptionTestSource";
        private const string VaultFolderPath = @"D:\temp\uvf\EncryptionTestVault";
        private const string DecryptedFolderPath = @"D:\temp\uvf\EncryptionTestDecrypted";
        private const string Password = "your-super-secret-password";
        private const bool OutputTreeInfo = false;
        private const string VaultFileName = "vault.uvf";

        private static Stopwatch _overallStopwatch = new Stopwatch();
        private static long _totalBytesProcessedOverall = 0;

        public static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: UvfConsole <encrypt|decrypt>");
                return;
            }

            string mode = args[0].ToLowerInvariant();
            Directory.CreateDirectory(VaultFolderPath);

            string vaultFilePath = Path.Combine(VaultFolderPath, VaultFileName);
            byte[] vaultFileContent;

            if (mode == "encrypt")
            {
                vaultFileContent = HandleEncryptMode(vaultFilePath);
                if (vaultFileContent == null) return;
            }
            else if (mode == "decrypt")
            {
                vaultFileContent = HandleDecryptMode(vaultFilePath);
                if (vaultFileContent == null) return;
            }
            else
            {
                Console.WriteLine("Invalid mode. Use 'encrypt' or 'decrypt'.");
                return;
            }

            ProcessVault(mode, vaultFileContent);
        }

        private static byte[] HandleEncryptMode(string vaultFilePath)
        {
            if (!Directory.Exists(SourceFolderPath))
            {
                Console.Error.WriteLine($"ERROR: Source folder not found at {SourceFolderPath}. Cannot encrypt.");
                return null;
            }

            if (OutputTreeInfo)
            {
                LogDirectoryTreeStructure(SourceFolderPath, "Source Directory Structure (Pre-Encryption):");
            }

            Console.WriteLine($"Starting encryption: {SourceFolderPath} -> {VaultFolderPath}");

            if (File.Exists(vaultFilePath))
            {
                Console.WriteLine($"Vault file found at: {vaultFilePath}. Loading existing vault.");
                return File.ReadAllBytes(vaultFilePath);
            }

            Console.WriteLine($"Vault file not found. Creating new one at: {vaultFilePath}");
            byte[] vaultFileContent = Vault.CreateNewUvfVaultFileContent(Password);
            File.WriteAllBytes(vaultFilePath, vaultFileContent);
            Console.WriteLine("New vault file created.");
            return vaultFileContent;
        }

        private static byte[] HandleDecryptMode(string vaultFilePath)
        {
            Console.WriteLine($"Starting decryption: {VaultFolderPath} -> {DecryptedFolderPath}");
            
            if (!File.Exists(vaultFilePath))
            {
                Console.Error.WriteLine($"ERROR: Vault file not found at {vaultFilePath}. Cannot decrypt.");
                return null;
            }

            Directory.CreateDirectory(DecryptedFolderPath);

            if (OutputTreeInfo)
            {
                LogDirectoryTreeStructure(VaultFolderPath, "Vault Directory Structure (Pre-Decryption):");
            }

            return File.ReadAllBytes(vaultFilePath);
        }

        private static void ProcessVault(string mode, byte[] vaultFileContent)
        {
            Console.WriteLine("Loading vault...");
            using (Vault vault = Vault.LoadUvfVault(vaultFileContent, Password))
            {
                Console.WriteLine("Vault loaded successfully.");

                DirectoryMetadata rootMetadata;
                string rootDirPhysicalPath = Path.Combine(VaultFolderPath, vault.GetRootDirectoryPath());
                string rootDirUvfPath = Path.Combine(rootDirPhysicalPath, "dir.uvf");

                if (mode == "encrypt")
                {
                    rootMetadata = HandleRootMetadataForEncryption(vault, rootDirUvfPath);
                    if (rootMetadata == null) return;

                    Console.WriteLine($"Encrypting root directory. Source: {SourceFolderPath}, Vault Root Physical Path: {rootDirPhysicalPath}");
                    Directory.CreateDirectory(rootDirPhysicalPath);

                    _overallStopwatch.Start();
                    _totalBytesProcessedOverall = ProcessDirectory(vault, SourceFolderPath, rootMetadata, rootDirPhysicalPath);
                    _overallStopwatch.Stop();

                    Console.WriteLine("Encryption complete.");
                    PrintSpeed("Encrypted", _totalBytesProcessedOverall, _overallStopwatch.Elapsed);

                    if (OutputTreeInfo)
                    {
                        LogDirectoryTreeStructure(VaultFolderPath, "Vault Directory Structure (Post-Encryption):");
                    }
                }
                else if (mode == "decrypt")
                {
                    rootMetadata = HandleRootMetadataForDecryption(vault, rootDirUvfPath);
                    if (rootMetadata == null) return;

                    Console.WriteLine($"Decrypting root directory. Vault Root Physical Path: {rootDirPhysicalPath}, Target: {DecryptedFolderPath}");

                    _overallStopwatch.Start();
                    _totalBytesProcessedOverall = DecryptDirectory(vault, rootMetadata, rootDirPhysicalPath, DecryptedFolderPath);
                    _overallStopwatch.Stop();

                    Console.WriteLine("Decryption complete.");
                    PrintSpeed("Decrypted", _totalBytesProcessedOverall, _overallStopwatch.Elapsed);

                    if (OutputTreeInfo)
                    {
                        LogDirectoryTreeStructure(DecryptedFolderPath, "Decrypted Directory Structure (Post-Decryption):");
                    }
                }
            }
        }

        private static DirectoryMetadata HandleRootMetadataForEncryption(Vault vault, string rootDirUvfPath)
        {
            if (File.Exists(rootDirUvfPath))
            {
                try
                {
                    Console.WriteLine($"Loading existing root dir.uvf from: {rootDirUvfPath}");
                    byte[] rootDirBytes = File.ReadAllBytes(rootDirUvfPath);
                    var metadata = vault.DecryptDirectoryMetadata(rootDirBytes);
                    Console.WriteLine("Successfully loaded and decrypted existing root metadata.");
                    return metadata;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Could not load or decrypt existing root dir.uvf ({ex.Message}). Initializing fresh root metadata.");
                    return vault.GetRootDirectoryMetadata();
                }
            }

            Console.WriteLine("Initializing fresh root metadata (no existing root dir.uvf found for encrypt mode).");
            return vault.GetRootDirectoryMetadata();
        }

        private static DirectoryMetadata HandleRootMetadataForDecryption(Vault vault, string rootDirUvfPath)
        {
            if (!File.Exists(rootDirUvfPath))
            {
                Console.Error.WriteLine($"ERROR: Root dir.uvf not found at {rootDirUvfPath}. Cannot decrypt.");
                Console.Error.WriteLine("FATAL: Cannot proceed with decryption without root metadata.");
                return null;
            }

            try
            {
                Console.WriteLine($"Loading root dir.uvf for decryption from: {rootDirUvfPath}");
                byte[] rootDirBytes = File.ReadAllBytes(rootDirUvfPath);
                var metadata = vault.DecryptDirectoryMetadata(rootDirBytes);
                Console.WriteLine("Successfully loaded and decrypted root metadata for decryption.");
                return metadata;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"FATAL: Could not load or decrypt root dir.uvf for decryption ({ex.Message}). Cannot proceed.");
                return null;
            }
        }

        private static long CalculateExpectedEncryptedSize(long sourceFileSize)
        {
            // Calculate how many complete chunks we'll need
            long completeChunks = sourceFileSize / Constants.PAYLOAD_SIZE;
            
            // Calculate the size of the final partial chunk (if any)
            long remainingBytes = sourceFileSize % Constants.PAYLOAD_SIZE;
            
            // Each chunk (including the final partial one if it exists) needs GCM_NONCE_SIZE + GCM_TAG_SIZE overhead
            long totalChunks = remainingBytes > 0 ? completeChunks + 1 : completeChunks;
            long totalOverhead = totalChunks * (Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE);
            
            // Add the file header size (from FileHeaderImpl)
            // Magic bytes (4) + Seed ID (4) + Nonce (12) + Content Key (32) + Tag (16) = 68 bytes
            long headerSize = 68;

            // Total size = file header + source file size + total chunk overhead
            long expectedSize = headerSize + sourceFileSize + totalOverhead;

            Console.WriteLine($"\nDebug - Expected Size Calculation:");
            Console.WriteLine($"  Source size: {sourceFileSize:N0} bytes");
            Console.WriteLine($"  Complete chunks: {completeChunks:N0}");
            Console.WriteLine($"  Remaining bytes: {remainingBytes:N0}");
            Console.WriteLine($"  Total chunks: {totalChunks:N0}");
            Console.WriteLine($"  Per-chunk overhead: {Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE} bytes");
            Console.WriteLine($"  Total chunk overhead: {totalOverhead:N0} bytes");
            Console.WriteLine($"  File header size: {headerSize} bytes");
            Console.WriteLine($"  Expected encrypted size: {expectedSize:N0} bytes\n");

            return expectedSize;
        }

        private static long ProcessDirectory(Vault vault, string sourceDir, DirectoryMetadata currentDirMetadata, string currentDirPhysicalVaultPath)
        {
            Console.WriteLine($"Processing directory: {sourceDir} -> {currentDirPhysicalVaultPath}");
            long bytesProcessedInThisCall = 0;

            // Save the current directory's metadata first
            byte[] encryptedMetadata = vault.EncryptDirectoryMetadata(currentDirMetadata);
            string dirUvfPath = Path.Combine(currentDirPhysicalVaultPath, "dir.uvf");
            File.WriteAllBytes(dirUvfPath, encryptedMetadata);

            // Process all files in the current directory
            foreach (string sourceFilePath in Directory.GetFiles(sourceDir))
            {
                string plainName = Path.GetFileName(sourceFilePath);
                long sourceFileSize = new FileInfo(sourceFilePath).Length;
                long expectedEncryptedSize = CalculateExpectedEncryptedSize(sourceFileSize);

                Console.WriteLine($"  Processing file: {plainName} ({sourceFileSize} bytes, expected encrypted size: {expectedEncryptedSize} bytes)");

                // Get encrypted name and create physical path for the encrypted file
                string encryptedName = vault.EncryptFilename(plainName, currentDirMetadata);
                string targetEncryptedFilePath = Path.Combine(currentDirPhysicalVaultPath, encryptedName);

                bool encryptThisFile = true;
                if (File.Exists(targetEncryptedFilePath))
                {
                    long existingFileSize = new FileInfo(targetEncryptedFilePath).Length;
                    Console.WriteLine($"    File already exists with size {existingFileSize} bytes");
                    
                    if (existingFileSize == expectedEncryptedSize)
                    {
                        Console.WriteLine("    Skipping file as it appears to be already encrypted correctly");
                        encryptThisFile = false;
                        bytesProcessedInThisCall += sourceFileSize; // Count it anyway for progress
                    }
                    else
                    {
                        Console.WriteLine($"    Existing file size ({existingFileSize}) doesn't match expected encrypted size ({expectedEncryptedSize}), re-encrypting");
                    }
                }

                if (encryptThisFile)
                {
                    try
                    {
                        long calculatedEncryptedSize = Vault.CalculateExpectedEncryptedSize(sourceFileSize);
                        Console.WriteLine($"\nSize Analysis for {plainName}:");
                        Console.WriteLine($"  Source size: {sourceFileSize:N0} bytes");
                        Console.WriteLine($"  Expected encrypted size: {calculatedEncryptedSize:N0} bytes");

                        using (FileStream sourceStream = File.OpenRead(sourceFilePath))
                        using (FileStream targetStream = File.Create(targetEncryptedFilePath))
                        using (Stream encryptingStream = vault.GetEncryptingStream(targetStream))
                        {
                            sourceStream.CopyTo(encryptingStream);
                        }
                        bytesProcessedInThisCall += sourceFileSize;
                        
                        // Verify the actual encrypted size matches expected
                        long actualEncryptedSize = new FileInfo(targetEncryptedFilePath).Length;
                        if (actualEncryptedSize != calculatedEncryptedSize)
                        {
                            Console.WriteLine($"  WARNING: Actual encrypted size ({actualEncryptedSize:N0}) differs from expected ({calculatedEncryptedSize:N0})");
                        }
                        else
                        {
                            Console.WriteLine($"  Encrypted successfully. Size verification passed.");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"    ERROR encrypting file {plainName}: {ex.Message}");
                    }
                }
            }

            // Process subdirectories
            foreach (string sourceSubDirPath in Directory.GetDirectories(sourceDir))
            {
                string plainSubDirName = Path.GetFileName(sourceSubDirPath);
                Console.WriteLine($"  Processing subdirectory: {plainSubDirName}");

                // Create new metadata for the subdirectory
                DirectoryMetadata subDirMetadata = vault.CreateNewDirectoryMetadata();
                string encryptedSubDirName = vault.EncryptFilename(plainSubDirName, currentDirMetadata);
                
                // Create the physical path for the encrypted subdirectory
                string subDirPhysicalVaultPath = Path.Combine(currentDirPhysicalVaultPath, encryptedSubDirName);
                string subDirUvfPath = Path.Combine(subDirPhysicalVaultPath, "dir.uvf");

                bool processSubDir = true;
                DirectoryMetadata existingSubDirMetadata = null;

                // Check if subdirectory already exists with valid metadata
                if (Directory.Exists(subDirPhysicalVaultPath) && File.Exists(subDirUvfPath))
                {
                    try
                    {
                        Console.WriteLine($"    Subdirectory already exists, checking metadata...");
                        byte[] existingMetadataBytes = File.ReadAllBytes(subDirUvfPath);
                        existingSubDirMetadata = vault.DecryptDirectoryMetadata(existingMetadataBytes);
                        
                        // If we can successfully decrypt the metadata, we can reuse this directory
                        Console.WriteLine($"    Reusing existing subdirectory structure (DirId: {existingSubDirMetadata.DirId})");
                        subDirMetadata = existingSubDirMetadata;
                        processSubDir = false;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"    Cannot reuse existing subdirectory: {ex.Message}");
                        // We'll create a new directory structure
                        processSubDir = true;
                    }
                }

                if (processSubDir)
                {
                    Console.WriteLine($"    Creating new subdirectory structure");
                    Directory.CreateDirectory(subDirPhysicalVaultPath);
                }

                // Recursively process the subdirectory
                bytesProcessedInThisCall += ProcessDirectory(vault, sourceSubDirPath, subDirMetadata, subDirPhysicalVaultPath);
            }

            return bytesProcessedInThisCall;
        }

        private static long CalculateExpectedDecryptedSize(long encryptedFileSize)
        {
            // Remove the file header size
            long sizeWithoutHeader = encryptedFileSize - 68; // 68 bytes header

            // Calculate how many complete chunks we have (each chunk has 28 bytes overhead)
            long totalOverhead = 0;
            long remainingBytes = sizeWithoutHeader;
            
            while (remainingBytes > 0)
            {
                // Each chunk has GCM_NONCE_SIZE + GCM_TAG_SIZE (28 bytes) overhead
                totalOverhead += Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE;
                remainingBytes -= Constants.CHUNK_SIZE;
            }

            // Expected decrypted size = encrypted size - header - total chunk overhead
            long expectedSize = encryptedFileSize - 68 - totalOverhead;

            Console.WriteLine($"\nDebug - Expected Decrypted Size Calculation:");
            Console.WriteLine($"  Encrypted size: {encryptedFileSize:N0} bytes");
            Console.WriteLine($"  Header size: 68 bytes");
            Console.WriteLine($"  Total chunk overhead: {totalOverhead:N0} bytes");
            Console.WriteLine($"  Expected decrypted size: {expectedSize:N0} bytes\n");

            return expectedSize;
        }

        private static long DecryptDirectory(Vault vault, DirectoryMetadata currentDirectoryMetadata, string currentDirPhysicalVaultPath, string targetDecryptedPath)
        {
            Console.WriteLine($"  DEBUG: DecryptDirectory START - CurrentDirPhysicalPath: {currentDirPhysicalVaultPath}, TargetDecryptedPath: {targetDecryptedPath}, CurrentDirMetadata (DirId: {currentDirectoryMetadata.DirId}, SeedId: {currentDirectoryMetadata.SeedId})");
            Console.WriteLine($"Decrypting directory from: {currentDirPhysicalVaultPath} -> to: {targetDecryptedPath} (DirId: {currentDirectoryMetadata.DirId})");
            
            Directory.CreateDirectory(targetDecryptedPath);

            long bytesProcessedInThisCall = 0;

            // Process all encrypted files in the current directory
            foreach (string encryptedFilePath in Directory.GetFiles(currentDirPhysicalVaultPath))
            {
                string encryptedName = Path.GetFileName(encryptedFilePath);
                if (encryptedName == "dir.uvf") continue; // Skip metadata file

                try
                {
                    string decryptedName = vault.DecryptFilename(encryptedName, currentDirectoryMetadata);
                    string targetDecryptedFilePath = Path.Combine(targetDecryptedPath, decryptedName);

                    long encryptedFileSize = new FileInfo(encryptedFilePath).Length;
                    long expectedDecryptedSize = Vault.CalculateExpectedDecryptedSize(encryptedFileSize);

                    Console.WriteLine($"\nSize Analysis for {encryptedName} -> {decryptedName}:");
                    Console.WriteLine($"  Encrypted size: {encryptedFileSize:N0} bytes");
                    Console.WriteLine($"  Expected decrypted size: {expectedDecryptedSize:N0} bytes");

                    bool decryptThisFile = true;
                    if (File.Exists(targetDecryptedFilePath))
                    {
                        long existingFileSize = new FileInfo(targetDecryptedFilePath).Length;
                        Console.WriteLine($"  File already exists with size {existingFileSize:N0} bytes");

                        if (existingFileSize == expectedDecryptedSize)
                        {
                            Console.WriteLine("  Skipping file as it appears to be already decrypted correctly");
                            decryptThisFile = false;
                            bytesProcessedInThisCall += expectedDecryptedSize; // Count it anyway for progress
                        }
                        else
                        {
                            Console.WriteLine($"  Existing file size ({existingFileSize:N0}) doesn't match expected decrypted size ({expectedDecryptedSize:N0}), re-decrypting");
                        }
                    }

                    if (decryptThisFile)
                    {
                        using (FileStream sourceStream = File.OpenRead(encryptedFilePath))
                        using (Stream decryptingStream = vault.GetDecryptingStream(sourceStream))
                        using (FileStream targetStream = File.Create(targetDecryptedFilePath))
                        {
                            decryptingStream.CopyTo(targetStream);
                        }

                        // Verify the actual decrypted size matches expected
                        long actualDecryptedSize = new FileInfo(targetDecryptedFilePath).Length;
                        if (actualDecryptedSize != expectedDecryptedSize)
                        {
                            Console.WriteLine($"  WARNING: Actual decrypted size ({actualDecryptedSize:N0}) differs from expected ({expectedDecryptedSize:N0})");
                        }
                        else
                        {
                            Console.WriteLine($"  Decrypted successfully. Size verification passed.");
                        }

                        bytesProcessedInThisCall += actualDecryptedSize;
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"    ERROR processing item '{encryptedName}': {ex.Message}");
                }
            }

            // Process all encrypted subdirectories
            foreach (string encryptedSubDirPath in Directory.GetDirectories(currentDirPhysicalVaultPath))
            {
                string encryptedSubDirName = Path.GetFileName(encryptedSubDirPath);

                try
                {
                    string decryptedSubDirName = vault.DecryptFilename(encryptedSubDirName, currentDirectoryMetadata);
                    string targetDecryptedSubDirPath = Path.Combine(targetDecryptedPath, decryptedSubDirName);

                    Console.WriteLine($"  Processing encrypted subdirectory: {encryptedSubDirName} -> {decryptedSubDirName}");

                    // Load and decrypt the subdirectory's metadata
                    string subDirUvfPath = Path.Combine(encryptedSubDirPath, "dir.uvf");
                    if (!File.Exists(subDirUvfPath))
                    {
                        Console.Error.WriteLine($"    ERROR: Missing dir.uvf in subdirectory: {encryptedSubDirPath}");
                        continue;
                    }

                    byte[] encryptedMetadata = File.ReadAllBytes(subDirUvfPath);
                    DirectoryMetadata subDirMetadata = vault.DecryptDirectoryMetadata(encryptedMetadata);

                    // Check if subdirectory is already decrypted with correct structure
                    bool decryptSubDir = true;
                    if (Directory.Exists(targetDecryptedSubDirPath))
                    {
                        Console.WriteLine($"    Subdirectory already exists at target location");
                        // We can't verify the content directly like with files, but we can check if it's a valid directory
                        if (Directory.GetFiles(targetDecryptedSubDirPath).Length > 0 || Directory.GetDirectories(targetDecryptedSubDirPath).Length > 0)
                        {
                            Console.WriteLine($"    Subdirectory appears to be already populated, will verify contents");
                            decryptSubDir = false;
                        }
                    }

                    if (decryptSubDir)
                    {
                        Directory.CreateDirectory(targetDecryptedSubDirPath);
                    }

                    // Recursively decrypt the subdirectory
                    bytesProcessedInThisCall += DecryptDirectory(vault, subDirMetadata, encryptedSubDirPath, targetDecryptedSubDirPath);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"    ERROR processing encrypted subdirectory '{encryptedSubDirName}': {ex.Message}");
                }
            }

            return bytesProcessedInThisCall;
        }

        private static void PrintSpeed(string operationLabel, long totalBytes, TimeSpan elapsed)
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

        private static void LogDirectoryTreeStructure(string rootPath, string description)
        {
            Console.WriteLine($"\n--- {description} ---");
            if (!Directory.Exists(rootPath) && !File.Exists(rootPath))
            {
                Console.WriteLine($"Path does not exist: {rootPath}");
                Console.WriteLine("--- End of Structure ---");
                Console.WriteLine();
                return;
            }
            
            Console.WriteLine(rootPath);
            LogDirectoryTreeRecursive(rootPath, "", true);
            Console.WriteLine("--- End of Structure ---");
            Console.WriteLine();
        }

        private static void LogDirectoryTreeRecursive(string currentPath, string indent, bool isLast)
        {
            if (!Directory.Exists(currentPath))
            {
                return;
            }

            var entries = Directory.GetFileSystemEntries(currentPath)
                                 .OrderBy(e => e)
                                 .ToList();

            for (int i = 0; i < entries.Count; i++)
            {
                string entry = entries[i];
                bool lastEntry = (i == entries.Count - 1);
                string marker = lastEntry ? "└───" : "├───";
                string entryName = Path.GetFileName(entry);

                Console.WriteLine($"{indent}{marker}{entryName}");

                if (Directory.Exists(entry))
                {
                    string newIndent = indent + (lastEntry ? "    " : "│   ");
                    LogDirectoryTreeRecursive(entry, newIndent, true);
                }
            }
        }
    }
} 