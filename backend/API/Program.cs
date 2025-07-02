using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecuNikLogX.API.Configuration;
using SecuNikLogX.API.Data;
using SecuNikLogX.API.Health;
using SecuNikLogX.API.Hubs;
using SecuNikLogX.API.Middleware;
using SecuNikLogX.API.Services;
using SecuNikLogX.Core.Interfaces;
using Serilog;
using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .Enrich.WithEnvironmentName()
    .WriteTo.Console()
    .WriteTo.File(
        Path.Combine("logs", "securniklogx-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        fileSizeLimitBytes: 10485760, // 10MB
        rollOnFileSizeLimit: true)
    .CreateLogger();

builder.Host.UseSerilog();

// Add configuration
builder.Configuration
    .SetBasePath(builder.Environment.ContentRootPath)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true)
    .AddEnvironmentVariables();

// Configure strongly-typed options
builder.Services.Configure<DatabaseOptions>(builder.Configuration.GetSection("Database"));
builder.Services.Configure<SecurityOptions>(builder.Configuration.GetSection("Security"));
builder.Services.Configure<FileStorageOptions>(builder.Configuration.GetSection("FileStorage"));
builder.Services.Configure<LoggingOptions>(builder.Configuration.GetSection("Logging"));
builder.Services.Configure<APIOptions>(builder.Configuration.GetSection("API"));
builder.Services.Configure<PerformanceOptions>(builder.Configuration.GetSection("Performance"));
builder.Services.Configure<ForensicsOptions>(builder.Configuration.GetSection("Forensics"));
builder.Services.Configure<SignalROptions>(builder.Configuration.GetSection("SignalR"));

// Entity Framework - SQLite only!
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Services from Batch 3 interfaces
builder.Services.AddScoped<IAnalysisService, AnalysisService>();
builder.Services.AddScoped<IParserService, ParserService>();
// Note: IRuleService would be registered here if RuleService exists

// Services from Batch 5 - NOW WITH INTERFACES
builder.Services.AddScoped<IAIService, AIService>();
builder.Services.AddScoped<IIOCService, IOCExtractor>(); // NOTE: IOCExtractor, not IOCService!

// Services from Batch 5 without interfaces
builder.Services.AddScoped<MITREMapper>(); // No interface, concrete class only
builder.Services.AddSingleton<PluginLoader>();

// New Batch 6 services
builder.Services.AddScoped<FileProcessingService>();
builder.Services.AddHostedService<BackgroundJobService>();

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("LocalDevelopment", policy =>
    {
        policy.WithOrigins(
                "http://localhost:3000",  // React development server
                "http://localhost:5173",  // Vite development server
                "http://localhost:5000",  // Production frontend
                "http://127.0.0.1:3000",
                "http://127.0.0.1:5173",
                "http://127.0.0.1:5000")
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    });
});

// SignalR
builder.Services.AddSignalR(options =>
{
    options.EnableDetailedErrors = builder.Environment.IsDevelopment();
    options.MaximumReceiveMessageSize = 1048576; // 1MB
    options.StreamBufferCapacity = 20;
    options.KeepAliveInterval = TimeSpan.FromSeconds(15);
    options.ClientTimeoutInterval = TimeSpan.FromSeconds(30);
});

// Response compression
builder.Services.AddResponseCompression(options =>
{
    options.EnableForHttps = true;
});

// Health checks
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("database", 
        tags: new[] { "db", "sql", "sqlite" },
        timeout: TimeSpan.FromSeconds(5));

// Add controllers with JSON options
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
        options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    });

// API documentation (Swagger)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "SecuNik LogX API",
        Version = "v1",
        Description = "Local-first digital forensics platform API"
    });
});

// Memory cache
builder.Services.AddMemoryCache();

// HTTP client factory
builder.Services.AddHttpClient();

// FluentValidation
builder.Services.AddValidatorsFromAssemblyContaining<Program>();

var app = builder.Build();

// Initialize database
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
    
    try
    {
        logger.LogInformation("Ensuring database is created and migrations are applied");
        dbContext.Database.EnsureCreated();
        
        // Run any pending migrations
        var pendingMigrations = dbContext.Database.GetPendingMigrations();
        if (pendingMigrations.Any())
        {
            logger.LogInformation("Applying {Count} pending migrations", pendingMigrations.Count());
            dbContext.Database.Migrate();
        }
        
        // Initialize database with seed data if needed
        var dbInitializer = new DbInitializer(dbContext, logger, builder.Configuration);
        await dbInitializer.InitializeAsync();
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "An error occurred while initializing the database");
        throw;
    }
}

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "SecuNik LogX API v1");
        c.RoutePrefix = "api-docs";
    });
}

// Middleware order is important!
app.UseResponseCompression();
app.UseCors("LocalDevelopment");
app.UseMiddleware<RequestLoggingMiddleware>(); // Our custom middleware
app.UseMiddleware<ErrorHandlingMiddleware>();   // From Batch 5
app.UseStaticFiles();
app.UseRouting();

// NO Authentication/Authorization yet - comes in later batches

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
    endpoints.MapHub<AnalysisHub>("/analysishub");
    endpoints.MapHealthChecks("/health", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
    {
        ResponseWriter = async (context, report) =>
        {
            context.Response.ContentType = "application/json";
            
            var response = new
            {
                status = report.Status.ToString(),
                checks = report.Entries.Select(x => new
                {
                    name = x.Key,
                    status = x.Value.Status.ToString(),
                    description = x.Value.Description,
                    duration = x.Value.Duration.TotalMilliseconds,
                    data = x.Value.Data
                }),
                totalDuration = report.TotalDuration.TotalMilliseconds
            };
            
            await context.Response.WriteAsync(
                JsonSerializer.Serialize(response, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    WriteIndented = true
                }));
        }
    });
    
    // Fallback for SPA routing (will be used in later batches)
    endpoints.MapFallbackToFile("index.html");
});

// Log application startup
app.Logger.LogInformation("SecuNik LogX API started successfully");
app.Logger.LogInformation("Environment: {Environment}", app.Environment.EnvironmentName);
app.Logger.LogInformation("Database: {Database}", builder.Configuration.GetConnectionString("DefaultConnection"));
app.Logger.LogInformation("Listening on: {Urls}", string.Join(", ", app.Urls));

// Ensure required directories exist
var requiredDirectories = new[]
{
    "./data/",
    "./uploads/",
    "./logs/",
    "./evidence/",
    "./quarantine/",
    "./temp/",
    "./reports/",
    "./plugins/"
};

foreach (var directory in requiredDirectories)
{
    if (!Directory.Exists(directory))
    {
        Directory.CreateDirectory(directory);
        app.Logger.LogInformation("Created directory: {Directory}", directory);
    }
}

// Run the application
app.Run();