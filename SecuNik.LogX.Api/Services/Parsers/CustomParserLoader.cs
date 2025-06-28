using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Entities;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using System.Reflection;
using System.Runtime.Loader;

namespace SecuNik.LogX.Api.Services.Parsers
{
    public class CustomParserLoader
    {
        private readonly ILogger<CustomParserLoader> _logger;
        private readonly Dictionary<Guid, Assembly> _loadedAssemblies;
        private readonly Dictionary<Guid, Type> _parserTypes;
        
        public CustomParserLoader(ILogger<CustomParserLoader> logger)
        {
            _logger = logger;
            _loadedAssemblies = new Dictionary<Guid, Assembly>();
            _parserTypes = new Dictionary<Guid, Type>();
        }
        
        public async Task<IParser?> LoadParserAsync(Parser parser)
        {
            try
            {
                if (parser.IsBuiltIn)
                {
                    throw new InvalidOperationException("Cannot load built-in parsers through custom loader");
                }
                
                // Check if already loaded
                if (_parserTypes.TryGetValue(parser.Id, out var cachedType))
                {
                    return CreateParserInstance(cachedType);
                }
                
                // Compile and load the parser
                var parserType = await CompileParserAsync(parser);
                if (parserType == null)
                {
                    return null;
                }
                
                _parserTypes[parser.Id] = parserType;
                return CreateParserInstance(parserType);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading custom parser {ParserName}", parser.Name);
                return null;
            }
        }
        
        public async Task<ValidationResult> ValidateParserCodeAsync(string code)
        {
            var result = new ValidationResult { IsValid = true };
            
            try
            {
                var syntaxTree = CSharpSyntaxTree.ParseText(code);
                var diagnostics = syntaxTree.GetDiagnostics();
                
                foreach (var diagnostic in diagnostics)
                {
                    if (diagnostic.Severity == DiagnosticSeverity.Error)
                    {
                        result.IsValid = false;
                        result.Errors.Add($"Syntax error at line {diagnostic.Location.GetLineSpan().StartLinePosition.Line + 1}: {diagnostic.GetMessage()}");
                    }
                    else if (diagnostic.Severity == DiagnosticSeverity.Warning)
                    {
                        result.Warnings.Add($"Warning at line {diagnostic.Location.GetLineSpan().StartLinePosition.Line + 1}: {diagnostic.GetMessage()}");
                    }
                }
                
                // Try to compile
                if (result.IsValid)
                {
                    var compilation = await CreateCompilationAsync(syntaxTree);
                    var compilationDiagnostics = compilation.GetDiagnostics();
                    
                    foreach (var diagnostic in compilationDiagnostics)
                    {
                        if (diagnostic.Severity == DiagnosticSeverity.Error)
                        {
                            result.IsValid = false;
                            result.Errors.Add($"Compilation error: {diagnostic.GetMessage()}");
                        }
                        else if (diagnostic.Severity == DiagnosticSeverity.Warning)
                        {
                            result.Warnings.Add($"Compilation warning: {diagnostic.GetMessage()}");
                        }
                    }
                }
                
                // Check for required interface implementation
                if (result.IsValid)
                {
                    var hasParserInterface = code.Contains("IParser") && code.Contains("ParseAsync");
                    if (!hasParserInterface)
                    {
                        result.Warnings.Add("Parser should implement IParser interface");
                    }
                }
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"Validation error: {ex.Message}");
            }
            
            return result;
        }
        
        public async Task<TestResult> TestParserAsync(Parser parser, string testContent)
        {
            var result = new TestResult();
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            try
            {
                var parserInstance = await LoadParserAsync(parser);
                if (parserInstance == null)
                {
                    result.Success = false;
                    result.ErrorMessage = "Failed to load parser";
                    return result;
                }
                
                // Test if parser can handle the content
                var canParse = await parserInstance.CanParseAsync("test.txt", testContent);
                if (!canParse)
                {
                    result.Success = false;
                    result.ErrorMessage = "Parser cannot handle the test content";
                    return result;
                }
                
                // Try to parse the content
                var parseResult = await parserInstance.ParseAsync("test.txt", testContent);
                
                result.Success = parseResult.Success;
                result.ErrorMessage = parseResult.ErrorMessage;
                result.Warnings = parseResult.Warnings;
                
                if (parseResult.Success)
                {
                    // Convert to RuleMatchResult format for consistency
                    // This is a simplified conversion - in a real scenario you might want more detailed results
                    result.Matches = new List<Core.Interfaces.RuleMatchResult>
                    {
                        new Core.Interfaces.RuleMatchResult
                        {
                            RuleName = parser.Name,
                            RuleType = Core.Entities.RuleType.Custom,
                            Severity = Core.Entities.ThreatLevel.Info,
                            MatchCount = parseResult.EventsCount,
                            Metadata = parseResult.Metadata
                        }
                    };
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                _logger.LogError(ex, "Error testing parser {ParserName}", parser.Name);
            }
            finally
            {
                stopwatch.Stop();
                result.ProcessingTime = stopwatch.Elapsed;
            }
            
            return result;
        }
        
        public void UnloadParser(Guid parserId)
        {
            try
            {
                _parserTypes.Remove(parserId);
                
                if (_loadedAssemblies.TryGetValue(parserId, out var assembly))
                {
                    _loadedAssemblies.Remove(parserId);
                    // Note: In .NET, we can't truly unload assemblies without using AssemblyLoadContext
                    // This is a simplified implementation
                }
                
                _logger.LogInformation("Unloaded parser {ParserId}", parserId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error unloading parser {ParserId}", parserId);
            }
        }
        
        private async Task<Type?> CompileParserAsync(Parser parser)
        {
            try
            {
                if (string.IsNullOrEmpty(parser.CodeContent))
                {
                    _logger.LogWarning("Parser {ParserName} has no code content", parser.Name);
                    return null;
                }
                
                var syntaxTree = CSharpSyntaxTree.ParseText(parser.CodeContent);
                var compilation = await CreateCompilationAsync(syntaxTree);
                
                using var ms = new MemoryStream();
                var result = compilation.Emit(ms);
                
                if (!result.Success)
                {
                    var errors = result.Diagnostics
                        .Where(d => d.Severity == DiagnosticSeverity.Error)
                        .Select(d => d.GetMessage());
                    
                    _logger.LogError("Compilation failed for parser {ParserName}: {Errors}", 
                        parser.Name, string.Join(", ", errors));
                    return null;
                }
                
                ms.Seek(0, SeekOrigin.Begin);
                var assembly = Assembly.Load(ms.ToArray());
                _loadedAssemblies[parser.Id] = assembly;
                
                // Find the parser class
                var parserType = assembly.GetTypes()
                    .FirstOrDefault(t => typeof(IParser).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract);
                
                if (parserType == null)
                {
                    _logger.LogError("No valid parser class found in compiled assembly for {ParserName}", parser.Name);
                    return null;
                }
                
                _logger.LogInformation("Successfully compiled parser {ParserName}", parser.Name);
                return parserType;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error compiling parser {ParserName}", parser.Name);
                return null;
            }
        }
        
        private async Task<CSharpCompilation> CreateCompilationAsync(SyntaxTree syntaxTree)
        {
            var references = new List<MetadataReference>
            {
                MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Console).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(IParser).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Text.Json.JsonDocument).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Text.RegularExpressions.Regex).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Microsoft.Extensions.Logging.ILogger).Assembly.Location),
                MetadataReference.CreateFromFile(Assembly.Load("System.Runtime").Location),
                MetadataReference.CreateFromFile(Assembly.Load("System.Collections").Location),
                MetadataReference.CreateFromFile(Assembly.Load("System.Linq").Location),
                MetadataReference.CreateFromFile(Assembly.Load("System.Threading.Tasks").Location)
            };
            
            // Add reference to netstandard if available
            try
            {
                references.Add(MetadataReference.CreateFromFile(Assembly.Load("netstandard").Location));
            }
            catch
            {
                // netstandard might not be available in all environments
            }
            
            return CSharpCompilation.Create(
                assemblyName: $"CustomParser_{Guid.NewGuid()}",
                syntaxTrees: new[] { syntaxTree },
                references: references,
                options: new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        }
        
        private IParser? CreateParserInstance(Type parserType)
        {
            try
            {
                // Try to create instance with logger parameter
                var loggerType = typeof(ILogger<>).MakeGenericType(parserType);
                var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
                
                var constructors = parserType.GetConstructors();
                
                // Try constructor with logger parameter
                var loggerConstructor = constructors.FirstOrDefault(c =>
                {
                    var parameters = c.GetParameters();
                    return parameters.Length == 1 && 
                           (parameters[0].ParameterType == typeof(ILogger) || 
                            parameters[0].ParameterType.IsAssignableFrom(typeof(ILogger)));
                });
                
                if (loggerConstructor != null)
                {
                    return (IParser?)Activator.CreateInstance(parserType, logger);
                }
                
                // Try parameterless constructor
                var defaultConstructor = constructors.FirstOrDefault(c => c.GetParameters().Length == 0);
                if (defaultConstructor != null)
                {
                    return (IParser?)Activator.CreateInstance(parserType);
                }
                
                _logger.LogWarning("No suitable constructor found for parser type {ParserType}", parserType.Name);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating parser instance of type {ParserType}", parserType.Name);
                return null;
            }
        }
        
        public Dictionary<string, object> GetLoaderStatistics()
        {
            return new Dictionary<string, object>
            {
                ["loaded_assemblies"] = _loadedAssemblies.Count,
                ["cached_parser_types"] = _parserTypes.Count,
                ["memory_usage"] = GC.GetTotalMemory(false)
            };
        }
    }
}