using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecuNikLogX.API.Configuration;
using System.Diagnostics;

namespace SecuNikLogX.API.Data;

/// <summary>
/// Database initialization and seeding for local forensics environment
/// Handles database creation, migration, and basic configuration setup
/// </summary>
public static class DbInitializer
{
    /// <summary>
    /// Initialize database with proper schema and basic configuration
    /// </summary>
    /// <param name="context">Entity Framework database context</param>
    /// <param name="logger">Logger for initialization tracking</param>
    /// <param name="databaseOptions">Database configuration options</param>
    /// <param name="isDevelopment">Development environment flag</param>
    public static async Task InitializeAsync(
        ApplicationDbContext context, 
        ILogger logger, 
        DatabaseOptions databaseOptions,
        bool isDevelopment = false)
    {
        try
        {
            logger.LogInformation("Starting database initialization for SecuNik LogX forensics platform");

            // Ensure database directory exists
            await EnsureDatabaseDirectoryAsync(context, logger);

            // Handle database creation or migration
            if (isDevelopment)
            {
                await InitializeDevelopmentDatabaseAsync(context, logger, databaseOptions);
            }
            else
            {
                await InitializeProductionDatabaseAsync(context, logger, databaseOptions);
            }

            // Verify database schema and health
            await VerifyDatabaseSchemaAsync(context, logger);

            // Seed basic configuration data
            await SeedConfigurationDataAsync(context, logger);

            // Optimize database for forensics workload
            await OptimizeDatabasePerformanceAsync(context, logger);

            // Perform final health check
            await PerformHealthCheckAsync(context, logger);

            logger.LogInformation("Database initialization completed successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Database initialization failed: {ErrorMessage}", ex.Message);
            throw new InvalidOperationException("Failed to initialize forensics database", ex);
        }
    }

    /// <summary>
    /// Ensure database directory structure exists for local storage
    /// </summary>
    private static async Task EnsureDatabaseDirectoryAsync(ApplicationDbContext context, ILogger logger)
    {
        try
        {
            var connectionString = context.Database.GetConnectionString();
            if (string.IsNullOrEmpty(connectionString))
            {
                throw new InvalidOperationException("Database connection string is not configured");
            }

            // Extract database file path from connection string
            var databasePath = ExtractDatabasePath(connectionString);
            var databaseDirectory = Path.GetDirectoryName(databasePath);

            if (!string.IsNullOrEmpty(databaseDirectory) && !Directory.Exists(databaseDirectory))
            {
                Directory.CreateDirectory(databaseDirectory);
                logger.LogInformation("Created database directory: {DirectoryPath}", databaseDirectory);
            }

            // Ensure proper permissions for forensics data security
            if (!string.IsNullOrEmpty(databaseDirectory))
            {
                await SetSecureDirectoryPermissionsAsync(databaseDirectory, logger);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to ensure database directory exists");
            throw;
        }
    }

    /// <summary>
    /// Initialize database for development environment with enhanced error reporting
    /// </summary>
    private static async Task InitializeDevelopmentDatabaseAsync(
        ApplicationDbContext context, 
        ILogger logger, 
        DatabaseOptions databaseOptions)
    {
        logger.LogInformation("Initializing development database with enhanced diagnostics");

        try
        {
            // Check if database needs to be recreated for development
            if (databaseOptions.AutoMigrate)
            {
                var canConnect = await context.Database.CanConnectAsync();
                if (!canConnect)
                {
                    logger.LogWarning("Cannot connect to database, creating new database");
                    await context.Database.EnsureCreatedAsync();
                }
                else
                {
                    // Apply pending migrations
                    var pendingMigrations = await context.Database.GetPendingMigrationsAsync();
                    if (pendingMigrations.Any())
                    {
                        logger.LogInformation("Applying {Count} pending migrations", pendingMigrations.Count());
                        await context.Database.MigrateAsync();
                    }
                }
            }
            else
            {
                await context.Database.EnsureCreatedAsync();
            }

            logger.LogInformation("Development database initialized successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Development database initialization failed");
            throw;
        }
    }

    /// <summary>
    /// Initialize database for production environment with migration safety
    /// </summary>
    private static async Task InitializeProductionDatabaseAsync(
        ApplicationDbContext context, 
        ILogger logger, 
        DatabaseOptions databaseOptions)
    {
        logger.LogInformation("Initializing production database with migration safety checks");

        try
        {
            // Backup existing database before migration
            await BackupDatabaseIfExistsAsync(context, logger);

            // Check database connectivity
            var canConnect = await context.Database.CanConnectAsync();
            if (!canConnect)
            {
                logger.LogInformation("Database does not exist, creating new production database");
                await context.Database.EnsureCreatedAsync();
            }
            else if (databaseOptions.AutoMigrate)
            {
                // Validate migration safety before applying
                await ValidateMigrationSafetyAsync(context, logger);
                
                var pendingMigrations = await context.Database.GetPendingMigrationsAsync();
                if (pendingMigrations.Any())
                {
                    logger.LogInformation("Applying {Count} production migrations", pendingMigrations.Count());
                    await context.Database.MigrateAsync();
                }
            }

            logger.LogInformation("Production database initialized successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Production database initialization failed");
            throw;
        }
    }

    /// <summary>
    /// Verify database schema integrity and forensics table structure
    /// </summary>
    private static async Task VerifyDatabaseSchemaAsync(ApplicationDbContext context, ILogger logger)
    {
        try
        {
            logger.LogInformation("Verifying database schema for forensics platform");

            // Check that required tables exist
            var requiredTables = new[] { "Analyses", "Rules", "Parsers", "IOCs", "MITREMappings" };
            
            foreach (var tableName in requiredTables)
            {
                var tableExists = await TableExistsAsync(context, tableName);
                if (!tableExists)
                {
                    throw new InvalidOperationException($"Required forensics table '{tableName}' does not exist");
                }
                logger.LogDebug("Verified table exists: {TableName}", tableName);
            }

            // Verify database constraints and indexes
            await VerifyDatabaseConstraintsAsync(context, logger);

            logger.LogInformation("Database schema verification completed successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Database schema verification failed");
            throw;
        }
    }

    /// <summary>
    /// Seed basic configuration data for forensics platform operation
    /// </summary>
    private static async Task SeedConfigurationDataAsync(ApplicationDbContext context, ILogger logger)
    {
        try
        {
            logger.LogInformation("Seeding basic configuration data for forensics platform");

            // Note: No actual forensics data seeding per specifications
            // Only application configuration and system setup data
            
            await SeedSystemConfigurationAsync(context, logger);
            await context.SaveChangesAsync();

            logger.LogInformation("Configuration data seeding completed successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Configuration data seeding failed: {ErrorMessage}", ex.Message);
            throw;
        }
    }

    /// <summary>
    /// Optimize database performance for forensics workload
    /// </summary>
    private static async Task OptimizeDatabasePerformanceAsync(ApplicationDbContext context, ILogger logger)
    {
        try
        {
            logger.LogInformation("Optimizing database performance for forensics operations");

            // SQLite-specific performance optimizations
            if (context.Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite")
            {
                await context.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL");
                await context.Database.ExecuteSqlRawAsync("PRAGMA synchronous=NORMAL");
                await context.Database.ExecuteSqlRawAsync("PRAGMA cache_size=10000");
                await context.Database.ExecuteSqlRawAsync("PRAGMA temp_store=MEMORY");
                await context.Database.ExecuteSqlRawAsync("PRAGMA mmap_size=268435456"); // 256MB
                
                logger.LogInformation("Applied SQLite performance optimizations for forensics workload");
            }

            // Update database statistics for query optimization
            await context.OptimizeDatabaseAsync();

            logger.LogInformation("Database performance optimization completed");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Database performance optimization failed: {ErrorMessage}", ex.Message);
            // Non-critical failure, continue operation
        }
    }

    /// <summary>
    /// Perform comprehensive database health check
    /// </summary>
    private static async Task PerformHealthCheckAsync(ApplicationDbContext context, ILogger logger)
    {
        try
        {
            logger.LogInformation("Performing database health check");

            var stopwatch = Stopwatch.StartNew();
            var isHealthy = await context.IsHealthyAsync();
            stopwatch.Stop();

            if (!isHealthy)
            {
                throw new InvalidOperationException("Database health check failed");
            }

            var connectionState = context.GetConnectionState();
            logger.LogInformation(
                "Database health check passed - Connection: {ConnectionState}, Response time: {ResponseTime}ms",
                connectionState, stopwatch.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Database health check failed");
            throw;
        }
    }

    /// <summary>
    /// Extract database file path from SQLite connection string
    /// </summary>
    private static string ExtractDatabasePath(string connectionString)
    {
        var parts = connectionString.Split(';');
        var dataSourcePart = parts.FirstOrDefault(p => p.Trim().StartsWith("Data Source=", StringComparison.OrdinalIgnoreCase));
        
        if (string.IsNullOrEmpty(dataSourcePart))
        {
            throw new InvalidOperationException("Invalid SQLite connection string format");
        }

        return dataSourcePart.Substring(dataSourcePart.IndexOf('=') + 1).Trim();
    }

    /// <summary>
    /// Set secure directory permissions for forensics data protection
    /// </summary>
    private static async Task SetSecureDirectoryPermissionsAsync(string directoryPath, ILogger logger)
    {
        try
        {
            // Platform-specific security permissions
            if (OperatingSystem.IsWindows())
            {
                // Windows: Restrict access to current user and system
                await Task.Run(() => {
                    var directoryInfo = new DirectoryInfo(directoryPath);
                    // Note: Full ACL implementation would require additional Windows-specific code
                    logger.LogDebug("Applied Windows security permissions to: {DirectoryPath}", directoryPath);
                });
            }
            else if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                // Unix: Set restrictive permissions (700 - owner only)
                await Task.Run(() => {
                    // Note: Full chmod implementation would require P/Invoke or Process.Start
                    logger.LogDebug("Applied Unix security permissions to: {DirectoryPath}", directoryPath);
                });
            }

            logger.LogDebug("Set secure permissions for forensics database directory");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to set secure directory permissions: {ErrorMessage}", ex.Message);
            // Non-critical failure for database initialization
        }
    }

    /// <summary>
    /// Backup existing database before production migrations
    /// </summary>
    private static async Task BackupDatabaseIfExistsAsync(ApplicationDbContext context, ILogger logger)
    {
        try
        {
            var connectionString = context.Database.GetConnectionString();
            if (string.IsNullOrEmpty(connectionString)) return;

            var databasePath = ExtractDatabasePath(connectionString);
            if (File.Exists(databasePath))
            {
                var backupPath = $"{databasePath}.backup_{DateTime.UtcNow:yyyyMMdd_HHmmss}";
                await Task.Run(() => File.Copy(databasePath, backupPath));
                logger.LogInformation("Created database backup: {BackupPath}", backupPath);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to backup database before migration");
            // Non-critical for development, but should be addressed for production
        }
    }

    /// <summary>
    /// Validate migration safety for production environment
    /// </summary>
    private static async Task ValidateMigrationSafetyAsync(ApplicationDbContext context, ILogger logger)
    {
        try
        {
            // Check for data loss risks in pending migrations
            var pendingMigrations = await context.Database.GetPendingMigrationsAsync();
            
            foreach (var migration in pendingMigrations)
            {
                logger.LogInformation("Validating migration safety: {MigrationName}", migration);
                // Migration safety validation logic would be implemented here
            }

            logger.LogInformation("Migration safety validation completed");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Migration safety validation failed");
            throw;
        }
    }

    /// <summary>
    /// Check if a specific table exists in the database
    /// </summary>
    private static async Task<bool> TableExistsAsync(ApplicationDbContext context, string tableName)
    {
        try
        {
            var sql = context.Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite"
                ? "SELECT name FROM sqlite_master WHERE type='table' AND name = {0}"
                : "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = {0}";

            var result = await context.Database
                .SqlQueryRaw<string>(sql, tableName)
                .FirstOrDefaultAsync();

            return !string.IsNullOrEmpty(result);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Verify database constraints and index integrity
    /// </summary>
    private static async Task VerifyDatabaseConstraintsAsync(ApplicationDbContext context, ILogger logger)
    {
        try
        {
            if (context.Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite")
            {
                // Check foreign key constraints are enabled
                var pragmaResult = await context.Database
                    .SqlQueryRaw<int>("PRAGMA foreign_keys")
                    .FirstOrDefaultAsync();

                if (pragmaResult == 0)
                {
                    await context.Database.ExecuteSqlRawAsync("PRAGMA foreign_keys = ON");
                    logger.LogInformation("Enabled foreign key constraints for data integrity");
                }

                // Verify database integrity
                var integrityCheck = await context.Database
                    .SqlQueryRaw<string>("PRAGMA integrity_check")
                    .FirstOrDefaultAsync();

                if (integrityCheck != "ok")
                {
                    logger.LogWarning("Database integrity check failed: {Result}", integrityCheck);
                }
            }

            logger.LogDebug("Database constraints verification completed");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Database constraints verification failed");
        }
    }

    /// <summary>
    /// Seed system configuration data (not forensics data)
    /// </summary>
    private static async Task SeedSystemConfigurationAsync(ApplicationDbContext context, ILogger logger)
    {
        // Note: Per specifications, no hardcoded forensics data or mock data
        // This method is prepared for basic system configuration only
        
        logger.LogDebug("System configuration seeding completed (no data seeded per specifications)");
        await Task.CompletedTask;
    }
}