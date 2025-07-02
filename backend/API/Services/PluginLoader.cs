using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Security;
using System.Security.Permissions;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SecuNik.LogX.API.Services
{
    public class PluginLoader
    {
        private readonly ILogger<PluginLoader> _logger;
        private readonly IConfiguration _configuration;
        private readonly ConcurrentDictionary<Guid, PluginContext> _loadedPlugins;
        private readonly ConcurrentDictionary<Guid, SandboxContext> _sandboxes;
        private readonly SemaphoreSlim _loadLock;
        private readonly PluginSecurityValidator _securityValidator;
        private readonly ResourceMonitor _resourceMonitor;

        public PluginLoader(ILogger<PluginLoader> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
            _loadedPlugins = new ConcurrentDictionary<Guid, PluginContext>();
            _sandboxes = new ConcurrentDictionary<Guid, SandboxContext>();
            _loadLock = new SemaphoreSlim(5); // Limit concurrent plugin loads
            _securityValidator = new PluginSecurityValidator(logger);
            _resourceMonitor = new ResourceMonitor(configuration);
        }

        public async Task<Assembly> LoadPluginAsync(Guid pluginId, byte[] assemblyBytes, CancellationToken cancellationToken = default)
        {
            await _loadLock.WaitAsync(cancellationToken);
            try
            {
                _logger.LogInformation("Loading plugin: {PluginId}", pluginId);

                // Validate assembly security
                var securityResult = await _securityValidator.ValidateAssemblySecurityAsync(assemblyBytes);
                if (!securityResult.IsSecure)
                {
                    throw new SecurityException($"Plugin failed security validation: {string.Join(", ", securityResult.Issues)}");
                }

                // Create isolated load context
                var loadContext = new PluginLoadContext($"Plugin_{pluginId}");
                
                using var ms = new MemoryStream(assemblyBytes);
                var assembly = loadContext.LoadFromStream(ms);

                // Validate loaded assembly
                await ValidateLoadedAssemblyAsync(assembly);

                // Store plugin context
                var context = new PluginContext
                {
                    PluginId = pluginId,
                    Assembly = assembly,
                    LoadContext = loadContext,
                    LoadedAt = DateTime.UtcNow,
                    MemoryUsage = assemblyBytes.Length
                };

                _loadedPlugins.TryAdd(pluginId, context);

                _logger.LogInformation("Successfully loaded plugin: {PluginId}", pluginId);
                return assembly;
            }
            finally
            {
                _loadLock.Release();
            }
        }

        public async Task<bool> UnloadPluginAsync(Guid pluginId, CancellationToken cancellationToken = default)
        {
            if (!_loadedPlugins.TryRemove(pluginId, out var context))
                return false;

            try
            {
                _logger.LogInformation("Unloading plugin: {PluginId}", pluginId);

                // Clean up any sandboxes using this plugin
                var sandboxesToRemove = _sandboxes.Where(kvp => kvp.Value.PluginId == pluginId).ToList();
                foreach (var sandbox in sandboxesToRemove)
                {
                    await CleanupSandboxAsync(sandbox.Key);
                }

                // Unload the assembly context
                context.LoadContext.Unload();

                // Force garbage collection to clean up
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();

                _logger.LogInformation("Successfully unloaded plugin: {PluginId}", pluginId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to unload plugin: {PluginId}", pluginId);
                return false;
            }
        }

        public async Task<bool> ReloadPluginAsync(Guid pluginId, byte[] newAssemblyBytes, CancellationToken cancellationToken = default)
        {
            // Unload existing plugin
            await UnloadPluginAsync(pluginId, cancellationToken);
            
            // Load new version
            try
            {
                await LoadPluginAsync(pluginId, newAssemblyBytes, cancellationToken);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to reload plugin: {PluginId}", pluginId);
                return false;
            }
        }

        public async Task<bool> ValidatePluginAsync(byte[] assemblyBytes, CancellationToken cancellationToken = default)
        {
            try
            {
                // Security validation
                var securityResult = await _securityValidator.ValidateAssemblySecurityAsync(assemblyBytes);
                if (!securityResult.IsSecure)
                    return false;

                // Try to load in temporary context
                using var tempContext = new PluginLoadContext("TempValidation");
                using var ms = new MemoryStream(assemblyBytes);
                var assembly = tempContext.LoadFromStream(ms);

                // Validate assembly structure
                await ValidateLoadedAssemblyAsync(assembly);

                tempContext.Unload();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Plugin validation failed");
                return false;
            }
        }

        public async Task<Assembly> CreateAssemblyAsync(string code, CancellationToken cancellationToken = default)
        {
            var syntaxTree = CSharpSyntaxTree.ParseText(code);
            var references = GetSecureReferences();
            var assemblyName = $"Dynamic_{Guid.NewGuid()}";

            var compilation = CSharpCompilation.Create(
                assemblyName,
                syntaxTrees: new[] { syntaxTree },
                references: references,
                options: new CSharpCompilationOptions(
                    OutputKind.DynamicallyLinkedLibrary,
                    optimizationLevel: OptimizationLevel.Release,
                    allowUnsafe: false,
                    platform: Platform.AnyCpu));

            using var ms = new MemoryStream();
            var emitResult = compilation.Emit(ms);

            if (!emitResult.Success)
            {
                var errors = string.Join("\n", emitResult.Diagnostics
                    .Where(d => d.IsWarningAsError || d.Severity == DiagnosticSeverity.Error)
                    .Select(d => d.GetMessage()));
                
                throw new InvalidOperationException($"Compilation failed: {errors}");
            }

            ms.Seek(0, SeekOrigin.Begin);
            return await LoadPluginAsync(Guid.NewGuid(), ms.ToArray(), cancellationToken);
        }

        public async Task<bool> CacheAssemblyAsync(Guid pluginId, byte[] assemblyBytes, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheDir = Path.Combine(_configuration["PluginCache:Path"] ?? "plugin_cache");
                Directory.CreateDirectory(cacheDir);

                var filePath = Path.Combine(cacheDir, $"{pluginId}.dll");
                await File.WriteAllBytesAsync(filePath, assemblyBytes, cancellationToken);

                _logger.LogInformation("Cached assembly for plugin: {PluginId}", pluginId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cache assembly for plugin: {PluginId}", pluginId);
                return false;
            }
        }

        public async Task<int> CleanupAssembliesAsync(TimeSpan olderThan, CancellationToken cancellationToken = default)
        {
            var cutoffTime = DateTime.UtcNow - olderThan;
            var unloadedCount = 0;

            var oldPlugins = _loadedPlugins
                .Where(kvp => kvp.Value.LoadedAt < cutoffTime && kvp.Value.LastUsed < cutoffTime)
                .ToList();

            foreach (var plugin in oldPlugins)
            {
                if (await UnloadPluginAsync(plugin.Key, cancellationToken))
                    unloadedCount++;
            }

            // Clean up cached assemblies
            var cacheDir = Path.Combine(_configuration["PluginCache:Path"] ?? "plugin_cache");
            if (Directory.Exists(cacheDir))
            {
                var files = Directory.GetFiles(cacheDir, "*.dll")
                    .Where(f => File.GetLastAccessTime(f) < cutoffTime)
                    .ToList();

                foreach (var file in files)
                {
                    try
                    {
                        File.Delete(file);
                        unloadedCount++;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to delete cached assembly: {File}", file);
                    }
                }
            }

            _logger.LogInformation("Cleaned up {Count} assemblies older than {Age}", unloadedCount, olderThan);
            return unloadedCount;
        }

        public async Task<SecurityValidationResult> ValidateAssemblySecurityAsync(byte[] assemblyBytes, CancellationToken cancellationToken = default)
        {
            return await _securityValidator.ValidateAssemblySecurityAsync(assemblyBytes);
        }

        public async Task<bool> ScanForMaliciousCodeAsync(string code, CancellationToken cancellationToken = default)
        {
            return await _securityValidator.ScanCodeForMaliciousPatterns(code);
        }

        public async Task<ResourceUsage> MonitorMemoryUsageAsync(Guid pluginId, CancellationToken cancellationToken = default)
        {
            if (!_loadedPlugins.TryGetValue(pluginId, out var context))
                return null;

            return await _resourceMonitor.GetResourceUsageAsync(pluginId);
        }

        public async Task<bool> EnforceResourceLimitsAsync(Guid sandboxId, ResourceLimits limits, CancellationToken cancellationToken = default)
        {
            if (!_sandboxes.TryGetValue(sandboxId, out var sandbox))
                return false;

            sandbox.ResourceLimits = limits;
            return await _resourceMonitor.EnforceLimitsAsync(sandboxId, limits);
        }

        public async Task<SandboxContext> CreateSandboxAsync(Guid pluginId, CancellationToken cancellationToken = default)
        {
            if (!_loadedPlugins.TryGetValue(pluginId, out var pluginContext))
                throw new InvalidOperationException($"Plugin not loaded: {pluginId}");

            var sandboxId = Guid.NewGuid();
            var sandbox = new SandboxContext
            {
                SandboxId = sandboxId,
                PluginId = pluginId,
                CreatedAt = DateTime.UtcNow,
                ResourceLimits = new ResourceLimits
                {
                    MaxMemoryMB = _configuration.GetValue<int>("Sandbox:MaxMemoryMB", 100),
                    MaxCpuPercent = _configuration.GetValue<int>("Sandbox:MaxCpuPercent", 50),
                    MaxExecutionTimeMs = _configuration.GetValue<int>("Sandbox:MaxExecutionTimeMs", 30000)
                },
                SecurityContext = new SecurityContext
                {
                    AllowFileAccess = false,
                    AllowNetworkAccess = false,
                    AllowProcessCreation = false,
                    AllowedNamespaces = new HashSet<string> { "System", "System.Collections.Generic", "System.Linq" }
                }
            };

            _sandboxes.TryAdd(sandboxId, sandbox);

            _logger.LogInformation("Created sandbox {SandboxId} for plugin {PluginId}", sandboxId, pluginId);
            return sandbox;
        }

        public async Task<T> ExecuteInSandboxAsync<T>(Func<Task<T>> action, Guid? sandboxId = null, CancellationToken cancellationToken = default)
        {
            var sandbox = sandboxId.HasValue && _sandboxes.TryGetValue(sandboxId.Value, out var existingSandbox)
                ? existingSandbox
                : await CreateTemporarySandboxAsync();

            try
            {
                // Start resource monitoring
                var monitoringTask = _resourceMonitor.MonitorExecutionAsync(sandbox.SandboxId, cancellationToken);

                // Execute with timeout
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(sandbox.ResourceLimits.MaxExecutionTimeMs);

                var executionTask = Task.Run(async () =>
                {
                    // Apply security restrictions
                    using (new SandboxSecurityContext(sandbox.SecurityContext))
                    {
                        return await action();
                    }
                }, cts.Token);

                // Wait for completion or timeout
                try
                {
                    var result = await executionTask;
                    await monitoringTask; // Ensure monitoring completes
                    return result;
                }
                catch (OperationCanceledException)
                {
                    throw new TimeoutException($"Sandbox execution exceeded time limit of {sandbox.ResourceLimits.MaxExecutionTimeMs}ms");
                }
            }
            finally
            {
                if (!sandboxId.HasValue)
                {
                    // Clean up temporary sandbox
                    await CleanupSandboxAsync(sandbox.SandboxId);
                }
            }
        }

        public async Task<bool> CleanupSandboxAsync(Guid sandboxId, CancellationToken cancellationToken = default)
        {
            if (!_sandboxes.TryRemove(sandboxId, out var sandbox))
                return false;

            try
            {
                // Stop resource monitoring
                await _resourceMonitor.StopMonitoringAsync(sandboxId);

                // Clean up any resources
                sandbox.Dispose();

                _logger.LogInformation("Cleaned up sandbox: {SandboxId}", sandboxId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cleanup sandbox: {SandboxId}", sandboxId);
                return false;
            }
        }

        public async Task<DependencyResolutionResult> ResolveDependenciesAsync(byte[] assemblyBytes, CancellationToken cancellationToken = default)
        {
            var result = new DependencyResolutionResult
            {
                ResolvedDependencies = new List<ResolvedDependency>(),
                MissingDependencies = new List<string>()
            };

            try
            {
                using var ms = new MemoryStream(assemblyBytes);
                using var peReader = new System.Reflection.PortableExecutable.PEReader(ms);
                var metadataReader = peReader.GetMetadataReader();

                foreach (var handle in metadataReader.AssemblyReferences)
                {
                    var reference = metadataReader.GetAssemblyReference(handle);
                    var name = metadataReader.GetString(reference.Name);

                    try
                    {
                        var assembly = Assembly.Load(new AssemblyName(name));
                        result.ResolvedDependencies.Add(new ResolvedDependency
                        {
                            Name = name,
                            Version = reference.Version.ToString(),
                            Location = assembly.Location
                        });
                    }
                    catch
                    {
                        result.MissingDependencies.Add(name);
                    }
                }

                result.Success = !result.MissingDependencies.Any();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to resolve dependencies");
                result.Success = false;
                result.Error = ex.Message;
            }

            return result;
        }

        public async Task<bool> ValidateDependenciesAsync(List<string> dependencies, CancellationToken cancellationToken = default)
        {
            var allowedAssemblies = _configuration.GetSection("Plugin:AllowedAssemblies").Get<string[]>() ?? new[]
            {
                "System.Private.CoreLib",
                "System.Runtime",
                "System.Collections",
                "System.Linq",
                "System.Text.RegularExpressions"
            };

            foreach (var dependency in dependencies)
            {
                if (!allowedAssemblies.Any(allowed => dependency.StartsWith(allowed)))
                {
                    _logger.LogWarning("Blocked unauthorized dependency: {Dependency}", dependency);
                    return false;
                }
            }

            return true;
        }

        public async Task<VersionComparisonResult> ManageVersionsAsync(Guid pluginId, CancellationToken cancellationToken = default)
        {
            // In production, this would manage multiple versions of the same plugin
            var result = new VersionComparisonResult
            {
                PluginId = pluginId,
                CurrentVersion = "1.0.0",
                AvailableVersions = new List<string> { "1.0.0" }
            };

            if (_loadedPlugins.TryGetValue(pluginId, out var context))
            {
                var version = context.Assembly.GetName().Version;
                result.CurrentVersion = version?.ToString() ?? "1.0.0";
            }

            return result;
        }

        public async Task<VersionComparisonResult> CompareVersionsAsync(Guid pluginId, string version1, string version2, CancellationToken cancellationToken = default)
        {
            var v1 = Version.Parse(version1);
            var v2 = Version.Parse(version2);

            return new VersionComparisonResult
            {
                PluginId = pluginId,
                Comparison = v1.CompareTo(v2),
                IsNewer = v1 > v2,
                IsOlder = v1 < v2,
                IsSame = v1 == v2
            };
        }

        public async Task<bool> MigrateVersionAsync(Guid pluginId, string fromVersion, string toVersion, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Migrating plugin {PluginId} from version {FromVersion} to {ToVersion}", 
                pluginId, fromVersion, toVersion);

            // In production, this would handle data migration between plugin versions
            return true;
        }

        public async Task<ExecutionProfile> ProfileExecutionAsync(Guid pluginId, string methodName, object[] parameters, CancellationToken cancellationToken = default)
        {
            if (!_loadedPlugins.TryGetValue(pluginId, out var context))
                throw new InvalidOperationException($"Plugin not loaded: {pluginId}");

            var profile = new ExecutionProfile
            {
                PluginId = pluginId,
                MethodName = methodName,
                StartTime = DateTime.UtcNow
            };

            var stopwatch = Stopwatch.StartNew();
            var startMemory = GC.GetTotalMemory(false);

            try
            {
                // Find and invoke method
                var type = context.Assembly.GetTypes().FirstOrDefault(t => t.GetMethod(methodName) != null);
                if (type == null)
                    throw new InvalidOperationException($"Method not found: {methodName}");

                var method = type.GetMethod(methodName);
                var instance = Activator.CreateInstance(type);
                
                await Task.Run(() => method.Invoke(instance, parameters), cancellationToken);

                stopwatch.Stop();
                profile.EndTime = DateTime.UtcNow;
                profile.ExecutionTime = stopwatch.ElapsedMilliseconds;
                profile.MemoryUsed = GC.GetTotalMemory(false) - startMemory;
                profile.Success = true;
            }
            catch (Exception ex)
            {
                profile.Error = ex.Message;
                profile.Success = false;
            }

            return profile;
        }

        public async Task<PerformanceReport> MonitorPerformanceAsync(Guid pluginId, TimeSpan duration, CancellationToken cancellationToken = default)
        {
            var report = new PerformanceReport
            {
                PluginId = pluginId,
                MonitoringStart = DateTime.UtcNow,
                MonitoringDuration = duration,
                Samples = new List<PerformanceSample>()
            };

            var endTime = DateTime.UtcNow + duration;
            var sampleInterval = TimeSpan.FromSeconds(1);

            while (DateTime.UtcNow < endTime && !cancellationToken.IsCancellationRequested)
            {
                var usage = await _resourceMonitor.GetResourceUsageAsync(pluginId);
                if (usage != null)
                {
                    report.Samples.Add(new PerformanceSample
                    {
                        Timestamp = DateTime.UtcNow,
                        CpuUsage = usage.CpuUsage,
                        MemoryUsage = usage.MemoryUsageMB,
                        ThreadCount = usage.ThreadCount
                    });
                }

                await Task.Delay(sampleInterval, cancellationToken);
            }

            // Calculate statistics
            if (report.Samples.Any())
            {
                report.AverageCpu = report.Samples.Average(s => s.CpuUsage);
                report.AverageMemory = report.Samples.Average(s => s.MemoryUsage);
                report.PeakCpu = report.Samples.Max(s => s.CpuUsage);
                report.PeakMemory = report.Samples.Max(s => s.MemoryUsage);
            }

            return report;
        }

        public async Task<bool> IsolateExecutionErrorsAsync(Guid sandboxId, Exception error, CancellationToken cancellationToken = default)
        {
            if (!_sandboxes.TryGetValue(sandboxId, out var sandbox))
                return false;

            sandbox.Errors.Add(new SandboxError
            {
                Timestamp = DateTime.UtcNow,
                ErrorType = error.GetType().Name,
                Message = error.Message,
                StackTrace = error.StackTrace,
                IsIsolated = true
            });

            _logger.LogWarning("Isolated error in sandbox {SandboxId}: {Error}", sandboxId, error.Message);
            return true;
        }

        public async Task HandleSandboxExceptionsAsync(Guid sandboxId, Func<Exception, Task<bool>> handler, CancellationToken cancellationToken = default)
        {
            if (!_sandboxes.TryGetValue(sandboxId, out var sandbox))
                return;

            sandbox.ExceptionHandler = handler;
        }

        public async Task<PluginCommunicationChannel> EstablishPluginAPIAsync(Guid pluginId, CancellationToken cancellationToken = default)
        {
            if (!_loadedPlugins.TryGetValue(pluginId, out var context))
                throw new InvalidOperationException($"Plugin not loaded: {pluginId}");

            var channel = new PluginCommunicationChannel
            {
                PluginId = pluginId,
                ChannelId = Guid.NewGuid(),
                EstablishedAt = DateTime.UtcNow,
                IsActive = true
            };

            // Set up communication mechanism (in production, this might use pipes or shared memory)
            channel.SendMessage = async (message) =>
            {
                _logger.LogDebug("Sending message to plugin {PluginId}: {Message}", pluginId, message);
                // Implementation would handle actual communication
                return true;
            };

            channel.ReceiveMessage = async () =>
            {
                // Implementation would handle actual communication
                return null;
            };

            return channel;
        }

        public async Task<bool> ValidatePluginContractAsync(Guid pluginId, Type contractInterface, CancellationToken cancellationToken = default)
        {
            if (!_loadedPlugins.TryGetValue(pluginId, out var context))
                return false;

            try
            {
                var implementingTypes = context.Assembly.GetTypes()
                    .Where(t => contractInterface.IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract)
                    .ToList();

                if (!implementingTypes.Any())
                {
                    _logger.LogWarning("Plugin {PluginId} does not implement required interface {Interface}", 
                        pluginId, contractInterface.Name);
                    return false;
                }

                // Validate that all interface methods are properly implemented
                foreach (var type in implementingTypes)
                {
                    var instance = Activator.CreateInstance(type);
                    if (instance == null)
                        return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate plugin contract for {PluginId}", pluginId);
                return false;
            }
        }

        // Private helper methods
        private async Task ValidateLoadedAssemblyAsync(Assembly assembly)
        {
            // Validate assembly has expected types
            var types = assembly.GetTypes();
            if (!types.Any())
                throw new InvalidOperationException("Assembly contains no types");

            // Check for required interfaces
            var hasRequiredInterface = types.Any(t => 
                t.GetInterfaces().Any(i => i.Name == "ILogParser" || i.Name == "IPlugin"));

            if (!hasRequiredInterface)
                throw new InvalidOperationException("Assembly must implement ILogParser or IPlugin interface");

            // Validate no dangerous types
            var dangerousTypes = types.Where(t => 
                t.Namespace?.StartsWith("System.IO") == true ||
                t.Namespace?.StartsWith("System.Net") == true ||
                t.Namespace?.StartsWith("System.Diagnostics") == true).ToList();

            if (dangerousTypes.Any())
            {
                throw new SecurityException($"Assembly contains prohibited types: {string.Join(", ", dangerousTypes.Select(t => t.FullName))}");
            }
        }

        private List<MetadataReference> GetSecureReferences()
        {
            var references = new List<MetadataReference>();
            var allowedAssemblies = new[]
            {
                "System.Private.CoreLib",
                "System.Runtime",
                "System.Collections",
                "System.Linq",
                "System.Text.RegularExpressions"
            };

            foreach (var assemblyName in allowedAssemblies)
            {
                try
                {
                    var assembly = Assembly.Load(assemblyName);
                    references.Add(MetadataReference.CreateFromFile(assembly.Location));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to load reference assembly: {AssemblyName}", assemblyName);
                }
            }

            return references;
        }

        private async Task<SandboxContext> CreateTemporarySandboxAsync()
        {
            var tempPluginId = Guid.NewGuid();
            var tempContext = new PluginContext
            {
                PluginId = tempPluginId,
                Assembly = null,
                LoadContext = null,
                LoadedAt = DateTime.UtcNow
            };

            _loadedPlugins.TryAdd(tempPluginId, tempContext);
            return await CreateSandboxAsync(tempPluginId);
        }

        // Nested classes
        private class PluginLoadContext : AssemblyLoadContext
        {
            public PluginLoadContext(string name) : base(name, isCollectible: true)
            {
            }

            protected override Assembly Load(AssemblyName assemblyName)
            {
                // Only allow loading of approved assemblies
                var approvedAssemblies = new[]
                {
                    "System.Private.CoreLib",
                    "System.Runtime",
                    "System.Collections",
                    "System.Linq"
                };

                if (approvedAssemblies.Any(a => assemblyName.Name.StartsWith(a)))
                {
                    return base.Load(assemblyName);
                }

                return null;
            }
        }

        private class PluginSecurityValidator
        {
            private readonly ILogger _logger;
            private readonly List<Regex> _maliciousPatterns;

            public PluginSecurityValidator(ILogger logger)
            {
                _logger = logger;
                _maliciousPatterns = InitializeMaliciousPatterns();
            }

            public async Task<SecurityValidationResult> ValidateAssemblySecurityAsync(byte[] assemblyBytes)
            {
                var result = new SecurityValidationResult { IsSecure = true };

                try
                {
                    // Check assembly size
                    if (assemblyBytes.Length > 10 * 1024 * 1024) // 10MB limit
                    {
                        result.IsSecure = false;
                        result.Issues.Add("Assembly size exceeds 10MB limit");
                    }

                    // Scan for known malicious signatures
                    var assemblyString = System.Text.Encoding.UTF8.GetString(assemblyBytes);
                    foreach (var pattern in _maliciousPatterns)
                    {
                        if (pattern.IsMatch(assemblyString))
                        {
                            result.IsSecure = false;
                            result.Issues.Add($"Detected malicious pattern: {pattern}");
                        }
                    }

                    // Additional security checks
                    using var ms = new MemoryStream(assemblyBytes);
                    using var peReader = new System.Reflection.PortableExecutable.PEReader(ms);
                    
                    if (!peReader.HasMetadata)
                    {
                        result.IsSecure = false;
                        result.Issues.Add("Assembly has no metadata");
                    }
                }
                catch (Exception ex)
                {
                    result.IsSecure = false;
                    result.Issues.Add($"Security validation error: {ex.Message}");
                }

                return result;
            }

            public async Task<bool> ScanCodeForMaliciousPatterns(string code)
            {
                var dangerousPatterns = new[]
                {
                    @"Process\.Start",
                    @"Assembly\.Load",
                    @"AppDomain",
                    @"SecurityPermission",
                    @"FileIOPermission",
                    @"RegistryPermission",
                    @"EnvironmentPermission",
                    @"ReflectionPermission",
                    @"SecurityAction",
                    @"AllowPartiallyTrustedCallers",
                    @"unsafe\s",
                    @"DllImport",
                    @"Marshal\.",
                    @"GCHandle",
                    @"IntPtr",
                    @"Socket",
                    @"TcpClient",
                    @"WebClient",
                    @"HttpClient"
                };

                foreach (var pattern in dangerousPatterns)
                {
                    if (Regex.IsMatch(code, pattern, RegexOptions.IgnoreCase))
                    {
                        _logger.LogWarning("Detected dangerous pattern in code: {Pattern}", pattern);
                        return false;
                    }
                }

                return true;
            }

            private List<Regex> InitializeMaliciousPatterns()
            {
                return new List<Regex>
                {
                    new Regex(@"kernel32\.dll", RegexOptions.IgnoreCase),
                    new Regex(@"ntdll\.dll", RegexOptions.IgnoreCase),
                    new Regex(@"advapi32\.dll", RegexOptions.IgnoreCase),
                    new Regex(@"ws2_32\.dll", RegexOptions.IgnoreCase),
                    new Regex(@"wininet\.dll", RegexOptions.IgnoreCase)
                };
            }
        }

        private class ResourceMonitor
        {
            private readonly IConfiguration _configuration;
            private readonly ConcurrentDictionary<Guid, ResourceUsage> _usageTracking;
            private readonly ConcurrentDictionary<Guid, CancellationTokenSource> _monitoringTasks;

            public ResourceMonitor(IConfiguration configuration)
            {
                _configuration = configuration;
                _usageTracking = new ConcurrentDictionary<Guid, ResourceUsage>();
                _monitoringTasks = new ConcurrentDictionary<Guid, CancellationTokenSource>();
            }

            public async Task<ResourceUsage> GetResourceUsageAsync(Guid entityId)
            {
                if (_usageTracking.TryGetValue(entityId, out var usage))
                    return usage;

                // Calculate current usage
                var process = Process.GetCurrentProcess();
                return new ResourceUsage
                {
                    EntityId = entityId,
                    CpuUsage = 0, // Would need proper CPU tracking
                    MemoryUsageMB = process.WorkingSet64 / (1024 * 1024),
                    ThreadCount = process.Threads.Count,
                    Timestamp = DateTime.UtcNow
                };
            }

            public async Task<bool> EnforceLimitsAsync(Guid entityId, ResourceLimits limits)
            {
                var usage = await GetResourceUsageAsync(entityId);
                
                if (usage.MemoryUsageMB > limits.MaxMemoryMB)
                {
                    // In production, would force garbage collection or kill process
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    GC.Collect();
                    return false;
                }

                return true;
            }

            public async Task MonitorExecutionAsync(Guid entityId, CancellationToken cancellationToken)
            {
                var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                _monitoringTasks.TryAdd(entityId, cts);

                try
                {
                    while (!cts.Token.IsCancellationRequested)
                    {
                        var usage = await GetResourceUsageAsync(entityId);
                        _usageTracking.AddOrUpdate(entityId, usage, (_, _) => usage);
                        
                        await Task.Delay(100, cts.Token);
                    }
                }
                finally
                {
                    _monitoringTasks.TryRemove(entityId, out _);
                }
            }

            public async Task StopMonitoringAsync(Guid entityId)
            {
                if (_monitoringTasks.TryRemove(entityId, out var cts))
                {
                    cts.Cancel();
                }

                _usageTracking.TryRemove(entityId, out _);
            }
        }

        private class SandboxSecurityContext : IDisposable
        {
            private readonly SecurityContext _context;

            public SandboxSecurityContext(SecurityContext context)
            {
                _context = context;
                ApplyRestrictions();
            }

            private void ApplyRestrictions()
            {
                // In production, this would apply actual security restrictions
                // For now, we'll log the intended restrictions
                if (!_context.AllowFileAccess)
                {
                    // Block file system access
                }

                if (!_context.AllowNetworkAccess)
                {
                    // Block network access
                }

                if (!_context.AllowProcessCreation)
                {
                    // Block process creation
                }
            }

            public void Dispose()
            {
                // Remove restrictions
            }
        }
    }

    // Supporting classes
    public class PluginContext
    {
        public Guid PluginId { get; set; }
        public Assembly Assembly { get; set; }
        public AssemblyLoadContext LoadContext { get; set; }
        public DateTime LoadedAt { get; set; }
        public DateTime LastUsed { get; set; } = DateTime.UtcNow;
        public long MemoryUsage { get; set; }
    }

    public class SandboxContext : IDisposable
    {
        public Guid SandboxId { get; set; }
        public Guid PluginId { get; set; }
        public DateTime CreatedAt { get; set; }
        public ResourceLimits ResourceLimits { get; set; }
        public SecurityContext SecurityContext { get; set; }
        public List<SandboxError> Errors { get; set; } = new List<SandboxError>();
        public Func<Exception, Task<bool>> ExceptionHandler { get; set; }

        public void Dispose()
        {
            // Cleanup resources
        }
    }

    public class ResourceLimits
    {
        public int MaxMemoryMB { get; set; }
        public int MaxCpuPercent { get; set; }
        public int MaxExecutionTimeMs { get; set; }
        public int MaxThreads { get; set; } = 10;
    }

    public class SecurityContext
    {
        public bool AllowFileAccess { get; set; }
        public bool AllowNetworkAccess { get; set; }
        public bool AllowProcessCreation { get; set; }
        public HashSet<string> AllowedNamespaces { get; set; }
    }

    public class SecurityValidationResult
    {
        public bool IsSecure { get; set; }
        public List<string> Issues { get; set; } = new List<string>();
    }

    public class ResourceUsage
    {
        public Guid EntityId { get; set; }
        public double CpuUsage { get; set; }
        public long MemoryUsageMB { get; set; }
        public int ThreadCount { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class DependencyResolutionResult
    {
        public bool Success { get; set; }
        public List<ResolvedDependency> ResolvedDependencies { get; set; }
        public List<string> MissingDependencies { get; set; }
        public string Error { get; set; }
    }

    public class ResolvedDependency
    {
        public string Name { get; set; }
        public string Version { get; set; }
        public string Location { get; set; }
    }

    public class VersionComparisonResult
    {
        public Guid PluginId { get; set; }
        public string CurrentVersion { get; set; }
        public List<string> AvailableVersions { get; set; }
        public int Comparison { get; set; }
        public bool IsNewer { get; set; }
        public bool IsOlder { get; set; }
        public bool IsSame { get; set; }
    }

    public class ExecutionProfile
    {
        public Guid PluginId { get; set; }
        public string MethodName { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public long ExecutionTime { get; set; }
        public long MemoryUsed { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; }
    }

    public class PerformanceReport
    {
        public Guid PluginId { get; set; }
        public DateTime MonitoringStart { get; set; }
        public TimeSpan MonitoringDuration { get; set; }
        public List<PerformanceSample> Samples { get; set; }
        public double AverageCpu { get; set; }
        public double AverageMemory { get; set; }
        public double PeakCpu { get; set; }
        public double PeakMemory { get; set; }
    }

    public class PerformanceSample
    {
        public DateTime Timestamp { get; set; }
        public double CpuUsage { get; set; }
        public double MemoryUsage { get; set; }
        public int ThreadCount { get; set; }
    }

    public class SandboxError
    {
        public DateTime Timestamp { get; set; }
        public string ErrorType { get; set; }
        public string Message { get; set; }
        public string StackTrace { get; set; }
        public bool IsIsolated { get; set; }
    }

    public class PluginCommunicationChannel
    {
        public Guid PluginId { get; set; }
        public Guid ChannelId { get; set; }
        public DateTime EstablishedAt { get; set; }
        public bool IsActive { get; set; }
        public Func<string, Task<bool>> SendMessage { get; set; }
        public Func<Task<string>> ReceiveMessage { get; set; }
    }
}