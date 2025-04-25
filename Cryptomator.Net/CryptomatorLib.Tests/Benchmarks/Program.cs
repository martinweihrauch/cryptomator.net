using System;

namespace CryptomatorLib.Tests.Benchmarks
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Cryptomator Benchmarks");
            Console.WriteLine("=====================");
            Console.WriteLine();

            if (args.Length == 0)
            {
                Console.WriteLine("Running all benchmarks...");
                BenchmarkRunner.RunAllBenchmarks();
                return;
            }

            BenchmarkRunner.Main(args);
        }
    }
}