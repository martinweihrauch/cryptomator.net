using System;
using System.Linq;
using System.Reflection;
using BenchmarkDotNet.Running;

namespace CryptomatorLib.Tests.Benchmarks
{
    /// <summary>
    /// Entry point for running benchmarks.
    /// </summary>
    public class Program
    {
#if BENCHMARKS
        static void Main(string[] args)
        {
            var assembly = typeof(Program).Assembly;
            BenchmarkSwitcher.FromAssembly(assembly).Run(args);
        }
#endif
    }
}