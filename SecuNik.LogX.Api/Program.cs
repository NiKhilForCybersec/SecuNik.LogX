using SecuNik.LogX.Api.Extensions;
using SecuNik.LogX.Api.Middleware;
using SecuNik.LogX.Api.Hubs;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.WriteIndented = false;
    });

// Add SecuNik LogX services
builder.Services.AddSecuNikLogXServices(builder.Configuration);

// Configure logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

if (builder.Environment.IsDevelopment())
{
    builder.Logging.SetMinimumLevel(LogLevel.Debug);
}
else
{
    builder.Logging.SetMinimumLevel(LogLevel.Information);
}

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "SecuNik LogX API v1");
        c.RoutePrefix = "swagger";
    });
}

// Middleware pipeline
app.UseMiddleware<ErrorHandlingMiddleware>();

app.UseRouting();

app.UseCors("AllowFrontend");

// Health checks
app.MapHealthChecks("/health", new HealthCheckOptions
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
                data = x.Value.Data
            }),
            duration = report.TotalDuration.TotalMilliseconds
        };
        
        await context.Response.WriteAsync(JsonSerializer.Serialize(response, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true
        }));
    }
});

app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready")
});

app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = _ => false
});

// API routes
app.MapControllers();

// SignalR hub
app.MapHub<AnalysisHub>("/hubs/analysis");

// Static files for frontend (if serving from same domain)
if (app.Environment.IsDevelopment())
{
    app.UseStaticFiles();
}

// Initialize the application
try
{
    app.Logger.LogInformation("Initializing SecuNik LogX...");
    await app.Services.InitializeSecuNikLogXAsync();
    app.Logger.LogInformation("SecuNik LogX initialized successfully");
}
catch (Exception ex)
{
    app.Logger.LogCritical(ex, "Failed to initialize SecuNik LogX");
    throw;
}

// Start the application
app.Logger.LogInformation("Starting SecuNik LogX API server...");
app.Logger.LogInformation("Environment: {Environment}", app.Environment.EnvironmentName);
app.Logger.LogInformation("Listening on: {Urls}", string.Join(", ", builder.WebHost.GetSetting("urls")?.Split(';') ?? new[] { "http://localhost:5000" }));

app.Run();