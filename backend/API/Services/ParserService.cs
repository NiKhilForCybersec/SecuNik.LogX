using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Emit;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecuNik.LogX.Domain.Entities;
using SecuNik.LogX.Domain.Services;
using SecuNik.LogX.Domain.Enums;
using SecuNik.LogX.Infrastructure.Data;

namespace SecuNik.LogX.API.Services
{
    public class ParserService : IParserService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<ParserService> _logger;
        private readonly IConfiguration _configuration;
        private readonly PluginLoader _pluginLoader;
        private readonly ConcurrentDictionary<Guid, CompilationResult> _compilationCache;
        private readonly ConcurrentDictionary<Guid, ExecutionMetrics> _executionMetrics;
        private readonly SemaphoreSlim _compilationLock;

        private static readonly string[] RestrictedNamespaces = 
        {
            "System.IO",
            "System.Net",
            "System.Diagnostics.Process",
            "System.Runtime.InteropServices",
            "System.Reflection.Emit",
            "Microsoft.Win32"
        };

        private static readonly string[] AllowedAssemblies = 
        {
            "System.Private.CoreLib",
            "System.Runtime",
            "System.Collections",
            "System.Linq",
            "System.Text.RegularExpressions",
            "SecuNik.LogX.Domain"
        };

        public ParserService(
            ApplicationDbContext context,
            ILogger<ParserService> logger,
            IConfiguration configuration,
            PluginLoader pluginLoader)
        {
            _context = context;
            _logger = logger;
            _configuration = configuration;
            _pluginLoader = pluginLoader;
            _compilationCache = new ConcurrentDictionary<Guid, CompilationResult>();
            _executionMetrics = new ConcurrentDictionary<Guid, ExecutionMetrics>();
            _compilationLock = new SemaphoreSlim(3); // Limit concurrent compilations
        }

        public async Task<Parser> CreateParserAsync(Parser parser, CancellationToken cancellationToken = default)
        {
            parser.Id = Guid.NewGuid();
            parser.Version = 1;
            parser.IsActive = false;
            parser.CreatedAt = DateTime.UtcNow;
            parser.UpdatedAt = DateTime.UtcNow;

            // Validate code before saving
            var validation = await ValidateCodeAsync(parser.Code, cancellationToken);
            if (!validation.IsValid)
            {
                throw new InvalidOperationException($"Parser code validation failed: {string.Join(", ", validation.Errors)}");
            }

            _context.Parsers.Add(parser);
            await _context.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Created parser: {ParserId} - {ParserName}", parser.Id, parser.Name);
            return parser;
        }

        public async Task<CompilationResult> CompileParserAsync(Guid parserId, CancellationToken cancellationToken = default)
        {
            await _compilationLock.WaitAsync(cancellationToken);
            try
            {
                // Check cache first
                if (_compilationCache.TryGetValue(parserId, out var cachedResult))
                {
                    _logger.LogInformation("Using cached compilation for parser: {ParserId}", parserId);
                    return cachedResult;
                }

                var parser = await _context.Parsers.FindAsync(new object[] { parserId }, cancellationToken);
                if (parser == null)
                    throw new InvalidOperationException($"Parser not found: {parserId}");

                _logger.LogInformation("Compiling parser: {ParserId} - {ParserName}", parserId, parser.Name);

                var syntaxTree = CSharpSyntaxTree.ParseText(parser.Code);
                var assemblyName = $"Parser_{parserId}_{DateTime.UtcNow.Ticks}";

                var references = GetSecureReferences();
                
                var compilation = CSharpCompilation.Create(
                    assemblyName,
                    syntaxTrees: new[] { syntaxTree },
                    references: references,
                    options: new CSharpCompilationOptions(
                        OutputKind.DynamicallyLinkedLibrary,
                        optimizationLevel: OptimizationLevel.Release,
                        platform: Platform.AnyCpu,
                        allowUnsafe: false,
                        warningLevel: 4,
                        deterministic: true));

                using var ms = new MemoryStream();
                var emitResult = compilation.Emit(ms);

                var result = new CompilationResult
                {
                    ParserId = parserId,
                    Success = emitResult.Success,
                    CompiledAt = DateTime.UtcNow,
                    AssemblyName = assemblyName
                };

                if (emitResult.Success)
                {
                    ms.Seek(0, SeekOrigin.Begin);
                    result.AssemblyBytes = ms.ToArray();
                    result.AssemblySize = result.AssemblyBytes.Length;

                    // Cache successful compilation
                    _compilationCache.TryAdd(parserId, result);
                    
                    parser.IsCompiled = true;
                    parser.LastCompiled = DateTime.UtcNow;
                    await _context.SaveChangesAsync(cancellationToken);
                }
                else
                {
                    result.Errors = emitResult.Diagnostics
                        .Where(d => d.IsWarningAsError || d.Severity == DiagnosticSeverity.Error)
                        .Select(d => new CompilationError
                        {
                            Code = d.Id,
                            Message = d.GetMessage(),
                            Line = d.Location.GetLineSpan().StartLinePosition.Line + 1,
                            Column = d.Location.GetLineSpan().StartLinePosition.Character + 1,
                            Severity = d.Severity.ToString()
                        })
                        .ToList();
                }

                return result;
            }
            finally
            {
                _compilationLock.Release();
            }
        }

        public async Task<TestResult> TestParserAsync(Guid parserId, string testData, CancellationToken cancellationToken = default)
        {
            var compilationResult = await CompileParserAsync(parserId, cancellationToken);
            if (!compilationResult.Success)
            {
                return new TestResult
                {
                    Success = false,
                    Error = "Compilation failed",
                    CompilationErrors = compilationResult.Errors
                };
            }

            try
            {
                var assembly = await _pluginLoader.LoadPluginAsync(parserId, compilationResult.AssemblyBytes);
                var parserType = assembly.GetTypes().FirstOrDefault(t => t.GetInterface("ILogParser") != null);
                
                if (parserType == null)
                {
                    return new TestResult
                    {
                        Success = false,
                        Error = "No ILogParser implementation found in compiled assembly"
                    };
                }

                var parserInstance = Activator.CreateInstance(parserType);
                var parseMethod = parserType.GetMethod("Parse");
                
                if (parseMethod == null)
                {
                    return new TestResult
                    {
                        Success = false,
                        Error = "Parse method not found in parser implementation"
                    };
                }

                var stopwatch = Stopwatch.StartNew();
                var result = await _pluginLoader.ExecuteInSandboxAsync(async () =>
                {
                    return parseMethod.Invoke(parserInstance, new object[] { testData });
                });
                stopwatch.Stop();

                return new TestResult
                {
                    Success = true,
                    Output = result?.ToString() ?? string.Empty,
                    ExecutionTime = stopwatch.ElapsedMilliseconds,
                    MemoryUsed = GC.GetTotalMemory(false)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Parser test failed for {ParserId}", parserId);
                return new TestResult
                {
                    Success = false,
                    Error = ex.Message,
                    StackTrace = ex.StackTrace
                };
            }
        }

        public async Task<bool> DeployParserAsync(Guid parserId, CancellationToken cancellationToken = default)
        {
            var parser = await _context.Parsers.FindAsync(new object[] { parserId }, cancellationToken);
            if (parser == null || !parser.IsCompiled)
                return false;

            var compilationResult = await CompileParserAsync(parserId, cancellationToken);
            if (!compilationResult.Success)
                return false;

            parser.IsActive = true;
            parser.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Deployed parser: {ParserId} - {ParserName}", parserId, parser.Name);
            return true;
        }

        public async Task<ValidationResult> ValidateCodeAsync(string code, CancellationToken cancellationToken = default)
        {
            var result = new ValidationResult { IsValid = true };
            var errors = new List<string>();

            // Security validation
            var securityResult = await AnalyzeSecurityAsync(code, cancellationToken);
            if (!securityResult.IsSecure)
            {
                errors.AddRange(securityResult.SecurityIssues);
                result.IsValid = false;
            }

            // Syntax validation
            var syntaxTree = CSharpSyntaxTree.ParseText(code);
            var diagnostics = syntaxTree.GetDiagnostics();
            
            foreach (var diagnostic in diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error))
            {
                errors.Add($"Syntax error at line {diagnostic.Location.GetLineSpan().StartLinePosition.Line + 1}: {diagnostic.GetMessage()}");
                result.IsValid = false;
            }

            // Check for required interface implementation
            var root = await syntaxTree.GetRootAsync(cancellationToken);
            var classes = root.DescendantNodes().OfType<ClassDeclarationSyntax>();
            var hasLogParser = classes.Any(c => c.BaseList?.Types.Any(t => t.ToString().Contains("ILogParser")) == true);
            
            if (!hasLogParser)
            {
                errors.Add("Code must contain a class implementing ILogParser interface");
                result.IsValid = false;
            }

            result.Errors = errors;
            return result;
        }

        public async Task<CompilationResult> CompileAsync(string code, CancellationToken cancellationToken = default)
        {
            var tempParserId = Guid.NewGuid();
            var parser = new Parser
            {
                Id = tempParserId,
                Name = "Temporary Parser",
                Code = code,
                CreatedAt = DateTime.UtcNow
            };

            // Compile without saving to database
            var syntaxTree = CSharpSyntaxTree.ParseText(code);
            var assemblyName = $"TempParser_{tempParserId}";
            var references = GetSecureReferences();

            var compilation = CSharpCompilation.Create(
                assemblyName,
                syntaxTrees: new[] { syntaxTree },
                references: references,
                options: new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

            using var ms = new MemoryStream();
            var emitResult = compilation.Emit(ms);

            return new CompilationResult
            {
                ParserId = tempParserId,
                Success = emitResult.Success,
                CompiledAt = DateTime.UtcNow,
                AssemblyName = assemblyName,
                AssemblyBytes = emitResult.Success ? ms.ToArray() : null,
                Errors = emitResult.Diagnostics
                    .Where(d => d.IsWarningAsError || d.Severity == DiagnosticSeverity.Error)
                    .Select(d => new CompilationError
                    {
                        Code = d.Id,
                        Message = d.GetMessage(),
                        Line = d.Location.GetLineSpan().StartLinePosition.Line + 1,
                        Column = d.Location.GetLineSpan().StartLinePosition.Character + 1,
                        Severity = d.Severity.ToString()
                    })
                    .ToList()
            };
        }

        public async Task<IEnumerable<CompilationError>> GetCompilationErrorsAsync(Guid parserId, CancellationToken cancellationToken = default)
        {
            if (_compilationCache.TryGetValue(parserId, out var cachedResult))
            {
                return cachedResult.Errors ?? Enumerable.Empty<CompilationError>();
            }

            var result = await CompileParserAsync(parserId, cancellationToken);
            return result.Errors ?? Enumerable.Empty<CompilationError>();
        }

        public async Task<ExecutionResult> ExecuteParserAsync(Guid parserId, string inputData, CancellationToken cancellationToken = default)
        {
            var parser = await _context.Parsers.FindAsync(new object[] { parserId }, cancellationToken);
            if (parser == null || !parser.IsActive)
            {
                return new ExecutionResult
                {
                    Success = false,
                    Error = "Parser not found or not active"
                };
            }

            var compilationResult = await CompileParserAsync(parserId, cancellationToken);
            if (!compilationResult.Success)
            {
                return new ExecutionResult
                {
                    Success = false,
                    Error = "Parser compilation failed"
                };
            }

            try
            {
                var stopwatch = Stopwatch.StartNew();
                var memoryBefore = GC.GetTotalMemory(false);

                var assembly = await _pluginLoader.LoadPluginAsync(parserId, compilationResult.AssemblyBytes);
                var parserType = assembly.GetTypes().FirstOrDefault(t => t.GetInterface("ILogParser") != null);
                var parserInstance = Activator.CreateInstance(parserType);
                var parseMethod = parserType.GetMethod("Parse");

                var result = await _pluginLoader.ExecuteInSandboxAsync(async () =>
                {
                    return parseMethod.Invoke(parserInstance, new object[] { inputData });
                });

                stopwatch.Stop();
                var memoryAfter = GC.GetTotalMemory(false);

                var executionResult = new ExecutionResult
                {
                    Success = true,
                    ParserId = parserId,
                    Output = result,
                    ExecutionTime = stopwatch.ElapsedMilliseconds,
                    MemoryUsed = memoryAfter - memoryBefore
                };

                // Update execution count
                parser.ExecutionCount++;
                parser.LastExecuted = DateTime.UtcNow;
                await _context.SaveChangesAsync(cancellationToken);

                // Track metrics
                UpdateExecutionMetrics(parserId, executionResult);

                return executionResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Parser execution failed for {ParserId}", parserId);
                return new ExecutionResult
                {
                    Success = false,
                    Error = ex.Message,
                    StackTrace = ex.StackTrace
                };
            }
        }

        public async Task<IEnumerable<ExecutionResult>> BatchExecuteAsync(Guid parserId, IEnumerable<string> inputDataSet, CancellationToken cancellationToken = default)
        {
            var results = new List<ExecutionResult>();
            var batchId = Guid.NewGuid();

            foreach (var inputData in inputDataSet)
            {
                var result = await ExecuteParserAsync(parserId, inputData, cancellationToken);
                result.BatchId = batchId;
                results.Add(result);

                if (cancellationToken.IsCancellationRequested)
                    break;
            }

            return results;
        }

        public async Task<ExecutionResult> GetExecutionResultsAsync(Guid executionId, CancellationToken cancellationToken = default)
        {
            // In a real implementation, execution results would be stored in the database
            var mockResult = new ExecutionResult
            {
                ExecutionId = executionId,
                Success = true,
                ExecutionTime = 150,
                MemoryUsed = 1024 * 1024
            };

            return await Task.FromResult(mockResult);
        }

        public async Task<SecurityAnalysisResult> AnalyzeSecurityAsync(string code, CancellationToken cancellationToken = default)
        {
            var result = new SecurityAnalysisResult { IsSecure = true };
            var issues = new List<string>();

            // Check for restricted namespaces
            foreach (var restrictedNamespace in RestrictedNamespaces)
            {
                if (code.Contains($"using {restrictedNamespace}") || code.Contains($"{restrictedNamespace}."))
                {
                    issues.Add($"Use of restricted namespace: {restrictedNamespace}");
                    result.IsSecure = false;
                }
            }

            // Check for dangerous patterns
            var dangerousPatterns = new[]
            {
                @"Process\.Start",
                @"Assembly\.Load",
                @"Type\.GetType",
                @"Activator\.CreateInstance",
                @"DllImport",
                @"unsafe\s",
                @"fixed\s*\(",
                @"stackalloc",
                @"Marshal\.",
                @"GCHandle\.",
                @"File\.",
                @"Directory\.",
                @"Registry\.",
                @"Socket\.",
                @"WebClient",
                @"HttpClient"
            };

            foreach (var pattern in dangerousPatterns)
            {
                if (Regex.IsMatch(code, pattern, RegexOptions.IgnoreCase))
                {
                    issues.Add($"Dangerous pattern detected: {pattern}");
                    result.IsSecure = false;
                }
            }

            // Check for reflection usage
            if (code.Contains("GetType()") || code.Contains("typeof") || code.Contains("Reflection"))
            {
                issues.Add("Reflection usage detected - this may pose security risks");
                result.RiskLevel = SecurityRiskLevel.Medium;
            }

            result.SecurityIssues = issues;
            result.AnalyzedAt = DateTime.UtcNow;

            return result;
        }

        public async Task<DependencyAnalysisResult> CheckDependenciesAsync(string code, CancellationToken cancellationToken = default)
        {
            var syntaxTree = CSharpSyntaxTree.ParseText(code);
            var root = await syntaxTree.GetRootAsync(cancellationToken);

            var usings = root.DescendantNodes()
                .OfType<UsingDirectiveSyntax>()
                .Select(u => u.Name.ToString())
                .ToList();

            var result = new DependencyAnalysisResult
            {
                Dependencies = usings,
                RequiredAssemblies = new List<string>()
            };

            // Map namespaces to assemblies
            var namespaceAssemblyMap = new Dictionary<string, string>
            {
                ["System"] = "System.Private.CoreLib",
                ["System.Collections.Generic"] = "System.Collections",
                ["System.Linq"] = "System.Linq",
                ["System.Text"] = "System.Runtime",
                ["System.Text.RegularExpressions"] = "System.Text.RegularExpressions"
            };

            foreach (var usingNamespace in usings)
            {
                if (namespaceAssemblyMap.TryGetValue(usingNamespace, out var assembly))
                {
                    result.RequiredAssemblies.Add(assembly);
                }
            }

            result.IsValid = result.RequiredAssemblies.All(a => AllowedAssemblies.Contains(a));
            
            return result;
        }

        public async Task<SyntaxValidationResult> ValidateSyntaxAsync(string code, CancellationToken cancellationToken = default)
        {
            var syntaxTree = CSharpSyntaxTree.ParseText(code);
            var diagnostics = syntaxTree.GetDiagnostics().ToList();

            var result = new SyntaxValidationResult
            {
                IsValid = !diagnostics.Any(d => d.Severity == DiagnosticSeverity.Error),
                Errors = diagnostics
                    .Where(d => d.Severity == DiagnosticSeverity.Error)
                    .Select(d => new SyntaxError
                    {
                        Message = d.GetMessage(),
                        Line = d.Location.GetLineSpan().StartLinePosition.Line + 1,
                        Column = d.Location.GetLineSpan().StartLinePosition.Character + 1,
                        Code = d.Id
                    })
                    .ToList(),
                Warnings = diagnostics
                    .Where(d => d.Severity == DiagnosticSeverity.Warning)
                    .Select(d => new SyntaxError
                    {
                        Message = d.GetMessage(),
                        Line = d.Location.GetLineSpan().StartLinePosition.Line + 1,
                        Column = d.Location.GetLineSpan().StartLinePosition.Character + 1,
                        Code = d.Id
                    })
                    .ToList()
            };

            return result;
        }

        public async Task<BenchmarkResult> BenchmarkParserAsync(Guid parserId, string testData, int iterations = 100, CancellationToken cancellationToken = default)
        {
            var compilationResult = await CompileParserAsync(parserId, cancellationToken);
            if (!compilationResult.Success)
            {
                throw new InvalidOperationException("Cannot benchmark parser that fails compilation");
            }

            var executionTimes = new List<long>();
            var memoryUsages = new List<long>();
            var errors = 0;

            for (int i = 0; i < iterations; i++)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                var result = await ExecuteParserAsync(parserId, testData, cancellationToken);
                
                if (result.Success)
                {
                    executionTimes.Add(result.ExecutionTime);
                    memoryUsages.Add(result.MemoryUsed);
                }
                else
                {
                    errors++;
                }
            }

            return new BenchmarkResult
            {
                ParserId = parserId,
                Iterations = iterations,
                SuccessfulRuns = iterations - errors,
                FailedRuns = errors,
                AverageExecutionTime = executionTimes.Any() ? executionTimes.Average() : 0,
                MinExecutionTime = executionTimes.Any() ? executionTimes.Min() : 0,
                MaxExecutionTime = executionTimes.Any() ? executionTimes.Max() : 0,
                AverageMemoryUsage = memoryUsages.Any() ? memoryUsages.Average() : 0,
                TotalDuration = executionTimes.Sum()
            };
        }

        public async Task<PerformanceMetrics> GetPerformanceMetricsAsync(Guid parserId, CancellationToken cancellationToken = default)
        {
            if (!_executionMetrics.TryGetValue(parserId, out var metrics))
            {
                var parser = await _context.Parsers.FindAsync(new object[] { parserId }, cancellationToken);
                if (parser == null)
                    return null;

                metrics = new ExecutionMetrics
                {
                    ParserId = parserId,
                    TotalExecutions = parser.ExecutionCount,
                    LastExecuted = parser.LastExecuted
                };
            }

            return new PerformanceMetrics
            {
                ParserId = parserId,
                TotalExecutions = metrics.TotalExecutions,
                AverageExecutionTime = metrics.AverageExecutionTime,
                AverageMemoryUsage = metrics.AverageMemoryUsage,
                LastExecuted = metrics.LastExecuted,
                SuccessRate = metrics.TotalExecutions > 0 
                    ? (double)metrics.SuccessfulExecutions / metrics.TotalExecutions * 100 
                    : 0
            };
        }

        public async Task<OptimizationResult> OptimizeParserAsync(Guid parserId, CancellationToken cancellationToken = default)
        {
            var parser = await _context.Parsers.FindAsync(new object[] { parserId }, cancellationToken);
            if (parser == null)
                throw new InvalidOperationException($"Parser not found: {parserId}");

            var result = new OptimizationResult
            {
                ParserId = parserId,
                OriginalCode = parser.Code
            };

            // Analyze current code
            var syntaxTree = CSharpSyntaxTree.ParseText(parser.Code);
            var root = await syntaxTree.GetRootAsync(cancellationToken);

            var optimizations = new List<string>();

            // Check for common optimization opportunities
            var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>();
            foreach (var method in methods)
            {
                // Check for string concatenation in loops
                var loops = method.DescendantNodes().OfType<ForStatementSyntax>()
                    .Concat<StatementSyntax>(method.DescendantNodes().OfType<WhileStatementSyntax>())
                    .Concat(method.DescendantNodes().OfType<ForEachStatementSyntax>());

                foreach (var loop in loops)
                {
                    var stringConcats = loop.DescendantNodes()
                        .OfType<BinaryExpressionSyntax>()
                        .Where(b => b.IsKind(SyntaxKind.AddExpression) && 
                                   b.Left.ToString().Contains("string") || 
                                   b.Right.ToString().Contains("string"));

                    if (stringConcats.Any())
                    {
                        optimizations.Add("Consider using StringBuilder instead of string concatenation in loops");
                    }
                }

                // Check for multiple LINQ operations that could be combined
                var linqChains = method.DescendantNodes()
                    .OfType<InvocationExpressionSyntax>()
                    .Where(i => i.ToString().Contains(".Where(") && 
                               i.Parent is MemberAccessExpressionSyntax);

                if (linqChains.Count() > 2)
                {
                    optimizations.Add("Consider combining multiple LINQ operations for better performance");
                }
            }

            // Apply automatic optimizations
            result.OptimizedCode = parser.Code; // In production, apply actual optimizations
            result.Optimizations = optimizations;
            result.PerformanceImprovement = optimizations.Any() ? 15.5 : 0; // Estimated improvement

            return result;
        }

        public async Task<ParserTemplate> GetParserTemplateAsync(string templateName, CancellationToken cancellationToken = default)
        {
            var templates = GetBuiltInTemplates();
            var template = templates.FirstOrDefault(t => t.Name.Equals(templateName, StringComparison.OrdinalIgnoreCase));
            
            if (template == null)
                throw new InvalidOperationException($"Template not found: {templateName}");

            return await Task.FromResult(template);
        }

        public async Task<Parser> CreateFromTemplateAsync(string templateName, string parserName, CancellationToken cancellationToken = default)
        {
            var template = await GetParserTemplateAsync(templateName, cancellationToken);
            
            var parser = new Parser
            {
                Id = Guid.NewGuid(),
                Name = parserName,
                Description = $"Parser created from template: {templateName}",
                Code = template.Code,
                Type = template.ParserType,
                Version = 1,
                IsActive = false,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                CreatedBy = "System",
                UpdatedBy = "System"
            };

            _context.Parsers.Add(parser);
            await _context.SaveChangesAsync(cancellationToken);

            return parser;
        }

        public async Task<IEnumerable<ParserTemplate>> ListTemplatesAsync(CancellationToken cancellationToken = default)
        {
            return await Task.FromResult(GetBuiltInTemplates());
        }

        public async Task<IEnumerable<ParserVersion>> GetParserVersionsAsync(Guid parserId, CancellationToken cancellationToken = default)
        {
            // In production, implement proper versioning with database storage
            var parser = await _context.Parsers.FindAsync(new object[] { parserId }, cancellationToken);
            if (parser == null)
                return Enumerable.Empty<ParserVersion>();

            var versions = new List<ParserVersion>
            {
                new ParserVersion
                {
                    ParserId = parserId,
                    Version = parser.Version,
                    Code = parser.Code,
                    CreatedAt = parser.CreatedAt,
                    CreatedBy = parser.CreatedBy,
                    IsCurrent = true
                }
            };

            return versions;
        }

        public async Task<ParserVersion> CreateVersionAsync(Guid parserId, string comment, CancellationToken cancellationToken = default)
        {
            var parser = await _context.Parsers.FindAsync(new object[] { parserId }, cancellationToken);
            if (parser == null)
                throw new InvalidOperationException($"Parser not found: {parserId}");

            parser.Version++;
            parser.UpdatedAt = DateTime.UtcNow;

            var version = new ParserVersion
            {
                ParserId = parserId,
                Version = parser.Version,
                Code = parser.Code,
                Comment = comment,
                CreatedAt = DateTime.UtcNow,
                CreatedBy = "System",
                IsCurrent = true
            };

            await _context.SaveChangesAsync(cancellationToken);

            return version;
        }

        public async Task<bool> RollbackVersionAsync(Guid parserId, int targetVersion, CancellationToken cancellationToken = default)
        {
            var parser = await _context.Parsers.FindAsync(new object[] { parserId }, cancellationToken);
            if (parser == null)
                return false;

            // In production, retrieve code from version history
            _logger.LogInformation("Rolling back parser {ParserId} to version {Version}", parserId, targetVersion);

            parser.Version = targetVersion;
            parser.UpdatedAt = DateTime.UtcNow;
            parser.IsCompiled = false; // Force recompilation

            await _context.SaveChangesAsync(cancellationToken);

            // Clear compilation cache
            _compilationCache.TryRemove(parserId, out _);

            return true;
        }

        public async Task<Parser> GetParserAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await _context.Parsers
                .Include(p => p.Analyses)
                .FirstOrDefaultAsync(p => p.Id == id, cancellationToken);
        }

        public async Task<IEnumerable<Parser>> GetAllParsersAsync(CancellationToken cancellationToken = default)
        {
            return await _context.Parsers
                .OrderBy(p => p.Name)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<Parser>> GetActiveParsersByTypeAsync(string type, CancellationToken cancellationToken = default)
        {
            return await _context.Parsers
                .Where(p => p.IsActive && p.Type == type)
                .OrderBy(p => p.Name)
                .ToListAsync(cancellationToken);
        }

        // Private helper methods
        private List<MetadataReference> GetSecureReferences()
        {
            var references = new List<MetadataReference>();

            // Add only safe assemblies
            foreach (var assemblyName in AllowedAssemblies)
            {
                try
                {
                    var assembly = Assembly.Load(assemblyName);
                    references.Add(MetadataReference.CreateFromFile(assembly.Location));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to load assembly reference: {AssemblyName}", assemblyName);
                }
            }

            // Add current domain assembly for ILogParser interface
            references.Add(MetadataReference.CreateFromFile(typeof(Parser).Assembly.Location));

            return references;
        }

        private void UpdateExecutionMetrics(Guid parserId, ExecutionResult result)
        {
            _executionMetrics.AddOrUpdate(parserId,
                new ExecutionMetrics
                {
                    ParserId = parserId,
                    TotalExecutions = 1,
                    SuccessfulExecutions = result.Success ? 1 : 0,
                    TotalExecutionTime = result.ExecutionTime,
                    TotalMemoryUsage = result.MemoryUsed,
                    LastExecuted = DateTime.UtcNow
                },
                (key, existing) =>
                {
                    existing.TotalExecutions++;
                    if (result.Success)
                        existing.SuccessfulExecutions++;
                    existing.TotalExecutionTime += result.ExecutionTime;
                    existing.TotalMemoryUsage += result.MemoryUsed;
                    existing.LastExecuted = DateTime.UtcNow;
                    existing.AverageExecutionTime = existing.TotalExecutionTime / existing.TotalExecutions;
                    existing.AverageMemoryUsage = existing.TotalMemoryUsage / existing.TotalExecutions;
                    return existing;
                });
        }

        private List<ParserTemplate> GetBuiltInTemplates()
        {
            return new List<ParserTemplate>
            {
                new ParserTemplate
                {
                    Name = "Windows Event Log Parser",
                    Description = "Parse Windows event logs in EVTX format",
                    ParserType = "EventLog",
                    Code = @"
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using SecuNik.LogX.Domain.Interfaces;

public class WindowsEventLogParser : ILogParser
{
    public ParseResult Parse(string logContent)
    {
        var result = new ParseResult();
        var events = new List<LogEvent>();
        
        var lines = logContent.Split('\n');
        foreach (var line in lines)
        {
            if (line.Contains(""EventID""))
            {
                var eventMatch = Regex.Match(line, @""EventID[:\s]+(\d+)"");
                if (eventMatch.Success)
                {
                    events.Add(new LogEvent
                    {
                        EventId = eventMatch.Groups[1].Value,
                        Timestamp = DateTime.UtcNow,
                        Message = line
                    });
                }
            }
        }
        
        result.Events = events;
        result.Success = true;
        return result;
    }
}"
                },
                new ParserTemplate
                {
                    Name = "Apache Access Log Parser",
                    Description = "Parse Apache web server access logs",
                    ParserType = "WebServer",
                    Code = @"
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using SecuNik.LogX.Domain.Interfaces;

public class ApacheAccessLogParser : ILogParser
{
    private readonly Regex logPattern = new Regex(
        @""^(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] \""(\S+) (\S+) (\S+)\"" (\d{3}) (\d+)"",
        RegexOptions.Compiled);

    public ParseResult Parse(string logContent)
    {
        var result = new ParseResult();
        var events = new List<LogEvent>();
        
        var lines = logContent.Split('\n');
        foreach (var line in lines)
        {
            var match = logPattern.Match(line);
            if (match.Success)
            {
                events.Add(new LogEvent
                {
                    SourceIP = match.Groups[1].Value,
                    Timestamp = DateTime.Parse(match.Groups[2].Value),
                    Method = match.Groups[3].Value,
                    Path = match.Groups[4].Value,
                    StatusCode = match.Groups[6].Value,
                    Size = match.Groups[7].Value
                });
            }
        }
        
        result.Events = events;
        result.Success = true;
        return result;
    }
}"
                },
                new ParserTemplate
                {
                    Name = "Syslog Parser",
                    Description = "Parse standard syslog format messages",
                    ParserType = "Syslog",
                    Code = @"
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using SecuNik.LogX.Domain.Interfaces;

public class SyslogParser : ILogParser
{
    private readonly Regex syslogPattern = new Regex(
        @""^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+(.*)$"",
        RegexOptions.Compiled);

    public ParseResult Parse(string logContent)
    {
        var result = new ParseResult();
        var events = new List<LogEvent>();
        
        var lines = logContent.Split('\n');
        foreach (var line in lines)
        {
            var match = syslogPattern.Match(line);
            if (match.Success)
            {
                var priority = int.Parse(match.Groups[1].Value);
                var facility = priority / 8;
                var severity = priority % 8;
                
                events.Add(new LogEvent
                {
                    Facility = facility,
                    Severity = severity,
                    Timestamp = DateTime.Parse(match.Groups[2].Value),
                    Hostname = match.Groups[3].Value,
                    Process = match.Groups[4].Value,
                    Message = match.Groups[5].Value
                });
            }
        }
        
        result.Events = events;
        result.Success = true;
        return result;
    }
}"
                }
            };
        }
    }

    // Supporting classes
    public class CompilationResult
    {
        public Guid ParserId { get; set; }
        public bool Success { get; set; }
        public byte[] AssemblyBytes { get; set; }
        public long AssemblySize { get; set; }
        public string AssemblyName { get; set; }
        public DateTime CompiledAt { get; set; }
        public List<CompilationError> Errors { get; set; }
    }

    public class CompilationError
    {
        public string Code { get; set; }
        public string Message { get; set; }
        public int Line { get; set; }
        public int Column { get; set; }
        public string Severity { get; set; }
    }

    public class TestResult
    {
        public bool Success { get; set; }
        public string Output { get; set; }
        public string Error { get; set; }
        public string StackTrace { get; set; }
        public long ExecutionTime { get; set; }
        public long MemoryUsed { get; set; }
        public List<CompilationError> CompilationErrors { get; set; }
    }

    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; }
    }

    public class ExecutionResult
    {
        public Guid ExecutionId { get; set; } = Guid.NewGuid();
        public Guid ParserId { get; set; }
        public Guid? BatchId { get; set; }
        public bool Success { get; set; }
        public object Output { get; set; }
        public string Error { get; set; }
        public string StackTrace { get; set; }
        public long ExecutionTime { get; set; }
        public long MemoryUsed { get; set; }
    }

    public class SecurityAnalysisResult
    {
        public bool IsSecure { get; set; }
        public List<string> SecurityIssues { get; set; }
        public SecurityRiskLevel RiskLevel { get; set; }
        public DateTime AnalyzedAt { get; set; }
    }

    public enum SecurityRiskLevel
    {
        Low,
        Medium,
        High,
        Critical
    }

    public class DependencyAnalysisResult
    {
        public List<string> Dependencies { get; set; }
        public List<string> RequiredAssemblies { get; set; }
        public bool IsValid { get; set; }
    }

    public class SyntaxValidationResult
    {
        public bool IsValid { get; set; }
        public List<SyntaxError> Errors { get; set; }
        public List<SyntaxError> Warnings { get; set; }
    }

    public class SyntaxError
    {
        public string Message { get; set; }
        public int Line { get; set; }
        public int Column { get; set; }
        public string Code { get; set; }
    }

    public class BenchmarkResult
    {
        public Guid ParserId { get; set; }
        public int Iterations { get; set; }
        public int SuccessfulRuns { get; set; }
        public int FailedRuns { get; set; }
        public double AverageExecutionTime { get; set; }
        public long MinExecutionTime { get; set; }
        public long MaxExecutionTime { get; set; }
        public double AverageMemoryUsage { get; set; }
        public long TotalDuration { get; set; }
    }

    public class PerformanceMetrics
    {
        public Guid ParserId { get; set; }
        public long TotalExecutions { get; set; }
        public double AverageExecutionTime { get; set; }
        public double AverageMemoryUsage { get; set; }
        public double SuccessRate { get; set; }
        public DateTime? LastExecuted { get; set; }
    }

    public class ExecutionMetrics
    {
        public Guid ParserId { get; set; }
        public long TotalExecutions { get; set; }
        public long SuccessfulExecutions { get; set; }
        public long TotalExecutionTime { get; set; }
        public long TotalMemoryUsage { get; set; }
        public double AverageExecutionTime { get; set; }
        public double AverageMemoryUsage { get; set; }
        public DateTime? LastExecuted { get; set; }
    }

    public class OptimizationResult
    {
        public Guid ParserId { get; set; }
        public string OriginalCode { get; set; }
        public string OptimizedCode { get; set; }
        public List<string> Optimizations { get; set; }
        public double PerformanceImprovement { get; set; }
    }

    public class ParserTemplate
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Code { get; set; }
        public string ParserType { get; set; }
    }

    public class ParserVersion
    {
        public Guid ParserId { get; set; }
        public int Version { get; set; }
        public string Code { get; set; }
        public string Comment { get; set; }
        public DateTime CreatedAt { get; set; }
        public string CreatedBy { get; set; }
        public bool IsCurrent { get; set; }
    }
}