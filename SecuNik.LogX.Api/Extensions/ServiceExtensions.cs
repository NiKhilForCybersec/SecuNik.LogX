using Microsoft.EntityFrameworkCore;
using SecuNik.LogX.Api.Data;
using SecuNik.LogX.Core.Configuration;
using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Api.Services.Storage;
using SecuNik.LogX.Api.Services.Rules;
using SecuNik.LogX.Api.Services.Parsers;
using SecuNik.LogX.Api.Services.Analysis;
using SecuNik.LogX.Api.Services.External;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace SecuNik.LogX.Api.Extensions
{
    public static class ServiceExtensions
    {
        public static IServiceCollection AddSecuNikLogXServices(this IServiceCollection services, IConfiguration configuration)
        {
            // Configuration
            services.Configure<StorageOptions>(configuration.GetSection(StorageOptions.SectionName));
            services.Configure<OpenAIOptions>(configuration.GetSection(OpenAIOptions.SectionName));
            services.Configure<VirusTotalOptions>(configuration.GetSection(VirusTotalOptions.SectionName));
            
            // Database
            services.AddDbContext<LogXDbContext>(options =>
            {
                var connectionString = configuration.GetConnectionString("DefaultConnection");
                options.UseSqlite(connectionString);
                options.EnableSensitiveDataLogging(false);
                options.EnableDetailedErrors(false);
            });
            
            // Core Services
            services.AddScoped<IStorageService, LocalStorageService>();
            services.AddScoped<IRuleEngine, RuleEngineService>();
            services.AddScoped<IAnalysisService, AnalysisService>();
            services.AddScoped<IThreatIntelligenceService, VirusTotalService>();
            
            // Parser Services
            services.AddScoped<ParserFactory>();
            services.AddScoped<CustomParserLoader>();
            services.AddScoped<WindowsEventLogParser>();
            services.AddScoped<JsonParser>();
            services.AddScoped<CsvParser>();
            services.AddScoped<TextLogParser>();
            services.AddScoped<SyslogParser>();
            services.AddScoped<CustomApacheLogParser>();
            
            // Rule Services
            services.AddScoped<RuleLoader>();
            services.AddScoped<RuleValidationService>();
            services.AddScoped<YaraRuleProcessor>();
            services.AddScoped<SigmaRuleProcessor>();
            services.AddScoped<StixRuleProcessor>();
            
            // Analysis Services
            services.AddScoped<AnalysisOrchestrator>();
            services.AddScoped<TimelineBuilder>();
            services.AddScoped<IOCExtractor>();
            services.AddScoped<ThreatScoringService>();
            services.AddScoped<MitreMapperService>();
            services.AddScoped<AIAnalyzerService>();
            
            // External Services
            services.AddHttpClient<VirusTotalService>();
            
            // Background Services
            services.AddHostedService<FileCleanupService>();
            
            // SignalR
            services.AddSignalR(options =>
            {
                options.EnableDetailedErrors = true;
                options.MaximumReceiveMessageSize = 1024 * 1024; // 1MB
                options.StreamBufferCapacity = 10;
            });
            
            // CORS
            services.AddCors(options =>
            {
                options.AddPolicy("AllowFrontend", policy =>
                {
                    policy.WithOrigins("http://localhost:3000", "http://localhost:5173")
                          .AllowAnyMethod()
                          .AllowAnyHeader()
                          .AllowCredentials();
                });
            });
            
            // API Documentation
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new() 
                { 
                    Title = "SecuNik LogX API", 
                    Version = "v1",
                    Description = "Local-first digital forensics and threat analysis platform API"
                });
                
                // Include XML comments
                var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                if (File.Exists(xmlPath))
                {
                    c.IncludeXmlComments(xmlPath);
                }
            });
            
            // Health Checks
            services.AddHealthChecks()
                .AddDbContextCheck<LogXDbContext>("database")
                .AddCheck<StorageHealthCheck>("storage")
                .AddCheck<RuleEngineHealthCheck>("rule_engine");
            
            return services;
        }
        
        public static async Task<IServiceProvider> InitializeSecuNikLogXAsync(this IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            
            // Initialize database
            var dbContext = scope.ServiceProvider.GetRequiredService<LogXDbContext>();
            await dbContext.Database.EnsureCreatedAsync();
            
            // Initialize storage directories
            var storageService = scope.ServiceProvider.GetRequiredService<IStorageService>();
            await InitializeStorageDirectoriesAsync(storageService);
            
            // Load rules
            var ruleLoader = scope.ServiceProvider.GetRequiredService<RuleLoader>();
            await ruleLoader.LoadAllRulesAsync();
            
            return serviceProvider;
        }
        
        private static async Task InitializeStorageDirectoriesAsync(IStorageService storageService)
        {
            // Create base directories if they don't exist
            var directories = new[]
            {
                "Storage",
                "Storage/Uploads",
                "Storage/Parsers",
                "Storage/Parsers/BuiltIn",
                "Storage/Parsers/UserDefined",
                "Storage/Rules",
                "Storage/Rules/YARA",
                "Storage/Rules/Sigma",
                "Storage/Rules/STIX",
                "Storage/Rules/Custom",
                "Storage/Results",
                "Storage/Temp"
            };
            
            foreach (var directory in directories)
            {
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
            }
            
            await Task.CompletedTask;
        }
    }
    
    // Health check implementations
    public class StorageHealthCheck : IHealthCheck
    {
        private readonly IStorageService _storageService;
        
        public StorageHealthCheck(IStorageService storageService)
        {
            _storageService = storageService;
        }
        
        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                var storageInfo = await _storageService.GetStorageInfoAsync(cancellationToken);
                
                var data = new Dictionary<string, object>
                {
                    ["total_space"] = storageInfo.TotalSpace,
                    ["used_space"] = storageInfo.UsedSpace,
                    ["available_space"] = storageInfo.AvailableSpace,
                    ["usage_percentage"] = storageInfo.TotalSpace > 0 ? (storageInfo.UsedSpace * 100.0 / storageInfo.TotalSpace) : 0
                };
                
                var usagePercentage = storageInfo.TotalSpace > 0 ? (storageInfo.UsedSpace * 100.0 / storageInfo.TotalSpace) : 0;
                
                if (usagePercentage > 90)
                {
                    return HealthCheckResult.Unhealthy("Storage usage is above 90%", data: data);
                }
                else if (usagePercentage > 80)
                {
                    return HealthCheckResult.Degraded("Storage usage is above 80%", data: data);
                }
                
                return HealthCheckResult.Healthy("Storage is healthy", data);
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy("Storage health check failed", ex);
            }
        }
    }
    
    public class RuleEngineHealthCheck : IHealthCheck
    {
        private readonly IRuleEngine _ruleEngine;
        
        public RuleEngineHealthCheck(IRuleEngine ruleEngine)
        {
            _ruleEngine = ruleEngine;
        }
        
        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                var activeRules = await _ruleEngine.GetActiveRulesAsync(cancellationToken: cancellationToken);
                
                var data = new Dictionary<string, object>
                {
                    ["total_active_rules"] = activeRules.Count,
                    ["yara_rules"] = activeRules.Count(r => r.Type == Core.Entities.RuleType.Yara),
                    ["sigma_rules"] = activeRules.Count(r => r.Type == Core.Entities.RuleType.Sigma),
                    ["custom_rules"] = activeRules.Count(r => r.Type == Core.Entities.RuleType.Custom)
                };
                
                if (activeRules.Count == 0)
                {
                    return HealthCheckResult.Degraded("No active rules loaded", data: data);
                }
                
                return HealthCheckResult.Healthy("Rule engine is healthy", data);
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy("Rule engine health check failed", ex);
            }
        }
    }
}