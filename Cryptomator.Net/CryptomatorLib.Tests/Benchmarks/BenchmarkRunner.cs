using System;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;
using CryptomatorLib.Tests.Benchmarks.v3;
using CryptomatorLib.Tests.Benchmarks;

namespace CryptomatorLib.Tests.Benchmarks
{
    public static class BenchmarkRunner
    {
        /// <summary>
        /// Runs all cryptomator benchmarks
        /// </summary>
        public static void RunAllBenchmarks()
        {
            var config = ManualConfig.Create(DefaultConfig.Instance)
                .WithOptions(ConfigOptions.DisableOptimizationsValidator);

            // Run v3 benchmarks
            BenchmarkDotNet.Running.BenchmarkRunner.Run<FileContentEncryptorBenchmark>(config);
            BenchmarkDotNet.Running.BenchmarkRunner.Run<FileContentDecryptorBenchmark>(config);

            // Run new crypto benchmarks
            BenchmarkDotNet.Running.BenchmarkRunner.Run<EncryptionBenchmarks>(config);
            BenchmarkDotNet.Running.BenchmarkRunner.Run<DecryptionBenchmarks>(config);
        }

        /// <summary>
        /// Runs only encryption benchmarks
        /// </summary>
        public static void RunEncryptionBenchmarks()
        {
            var config = ManualConfig.Create(DefaultConfig.Instance)
                .WithOptions(ConfigOptions.DisableOptimizationsValidator);

            // Run v3 encryption benchmarks
            BenchmarkDotNet.Running.BenchmarkRunner.Run<FileContentEncryptorBenchmark>(config);

            // Run new encryption benchmarks
            BenchmarkDotNet.Running.BenchmarkRunner.Run<EncryptionBenchmarks>(config);
        }

        /// <summary>
        /// Runs only decryption benchmarks
        /// </summary>
        public static void RunDecryptionBenchmarks()
        {
            var config = ManualConfig.Create(DefaultConfig.Instance)
                .WithOptions(ConfigOptions.DisableOptimizationsValidator);

            // Run v3 decryption benchmarks
            BenchmarkDotNet.Running.BenchmarkRunner.Run<FileContentDecryptorBenchmark>(config);

            // Run new decryption benchmarks
            BenchmarkDotNet.Running.BenchmarkRunner.Run<DecryptionBenchmarks>(config);
        }

        // Main method removed to avoid multiple entry points conflict in test project
    }
}