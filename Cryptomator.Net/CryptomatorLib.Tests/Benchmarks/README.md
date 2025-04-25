# Cryptomator Benchmarks

This directory contains benchmarks for the Cryptomator.Net library using BenchmarkDotNet.

## Running Benchmarks

You can run the benchmarks in several ways:

### From the Command Line

1. Navigate to the Benchmarks project directory
2. Run the benchmarks:

```bash
# Run all benchmarks
dotnet run -c Release

# Run only encryption benchmarks
dotnet run -c Release -- encrypt

# Run only decryption benchmarks
dotnet run -c Release -- decrypt
```

The `-c Release` flag ensures the benchmarks run in Release configuration mode, which is recommended for accurate performance measurements.

### From Visual Studio

1. Set the Benchmarks project as the startup project
2. Configure project launch settings to pass appropriate arguments if needed
3. Run the project in Release mode

## Available Benchmarks

- **Encryption Benchmarks**: Test the performance of different encryption operations
- **Decryption Benchmarks**: Test the performance of different decryption operations

## Benchmark Results

Benchmark results will be displayed in the console and also saved to the `BenchmarkDotNet.Artifacts` directory in the project folder. 