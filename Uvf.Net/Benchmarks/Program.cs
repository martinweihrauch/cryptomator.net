using System;
using System.Linq;
using System.Reflection;
using BenchmarkDotNet.Running;

namespace UvfLib.Benchmarks // Adjust namespace to match project
{
    /// <summary>
    /// Entry point for running benchmarks.
    /// </summary>
    public class Program
    {
        // Main entry point
        static void Main(string[] args)
        {
            Console.WriteLine("Running benchmarks defined in this assembly...");
            // Use BenchmarkSwitcher to find and run benchmarks
            var summary = BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
            Console.WriteLine("\nBenchmark run complete.");
            // You can optionally inspect the summary object here
        }
    }
}
