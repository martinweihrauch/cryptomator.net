using System;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Reports;
using BenchmarkDotNet.Loggers;
using System.Linq;
using System.Reflection;

namespace CryptomatorLib.Tests.Benchmarks
{
    /// <summary>
    /// Entry point for running benchmarks.
    /// </summary>
    public class BenchmarkProgram
    {
#if !MSTEST
        /// <summary>
        /// Main entry point (only active when not running as MSTest)
        /// </summary>
        /// <param name="args">Command line arguments</param>
        public static void Main(string[] args)
        {
            var config = ManualConfig.Create(DefaultConfig.Instance)
                .WithSummaryStyle(SummaryStyle.Default.WithMaxParameterColumnWidth(50))
                .AddDiagnoser(MemoryDiagnoser.Default)
                .AddExporter(HtmlExporter.Default, MarkdownExporter.GitHub);

            var logger = ConsoleLogger.Default;

            var benchmarks = typeof(BenchmarkProgram).Assembly.GetTypes()
                .Where(t => t.GetMethods().Any(m => m.GetCustomAttributes(typeof(BenchmarkDotNet.Attributes.BenchmarkAttribute), false).Any()))
                .ToArray();

            BenchmarkRunner.Run(benchmarks, config);
        }
#endif
    }
}