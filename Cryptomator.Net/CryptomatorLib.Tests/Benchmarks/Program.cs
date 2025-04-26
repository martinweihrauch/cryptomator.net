using System;
using System.Reflection;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;
using CryptomatorLib.Tests.Benchmarks.v3;

namespace CryptomatorLib.Tests.Benchmarks
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Cryptomator Benchmarks");
            Console.WriteLine("=====================");
            Console.WriteLine();

            // With BenchmarkDotNet 0.14.0, we need to use this syntax
            BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
        }
    }
}