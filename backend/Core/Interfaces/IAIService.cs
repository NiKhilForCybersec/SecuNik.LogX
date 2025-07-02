using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using SecuNikLogX.API.Data;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SecuNikLogX.API.Health
{
    public class DatabaseHealthCheck : IHealthCheck
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly IConfiguration _configuration;
        private readonly ILogger<DatabaseHealthCheck> _logger;

        public DatabaseHealthCheck(
            ApplicationDbContext dbContext,
            IConfiguration configuration,
            ILogger<DatabaseHealthCheck> logger)
        {
            _dbContext = dbContext;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<HealthCheckResult> CheckHealthAsync(
            HealthCheckContext context,
            CancellationToken cancellationToken = default)
        {
            var data = new Dictionary<string, object>();
            var healthCheckResults = new List<HealthCheckItem>();

            try
            {
                // 1. Check database connection
                var connectionResult = await CheckDatabaseConnectionAsync(cancellationToken);
                healthCheckResults.Add(connectionResult);
                data["Connection"] = connectionResult.Status;

                if (connectionResult.Status != "Healthy")
                {
                    return HealthCheckResult.Unhealthy(
                        "Database connection failed",
                        data: data);
                }

                // 2. Check migration status
                var migrationResult = await CheckMigrationStatusAsync(cancellationToken);
                healthCheckResults.Add(migrationResult);
                data["Migrations"] = migrationResult.Status;

                // 3. Check disk space for database file
                var diskSpaceResult = await CheckDiskSpaceAsync();
                healthCheckResults.Add(diskSpaceResult);
                data["DiskSpace"] = diskSpaceResult.Status;
                data["DiskSpaceDetails"] = diskSpaceResult.Details;

                // 4. Check table existence
                var tableResult = await CheckTablesAsync(cancellationToken);
                healthCheckResults.Add(tableResult);
                data["Tables"] = tableResult.Status;
                data["TableDetails"] = tableResult.Details;

                // 5. Query performance test
                var performanceResult = await CheckQueryPerformanceAsync(cancellationToken);
                healthCheckResults.Add(performanceResult);
                data["QueryPerformance"] = performanceResult.Status;
                data["QueryPerformanceMs"] = performanceResult.Details["ElapsedMs"];

                // 6. Database file size check
                var fileSizeResult = await CheckDatabaseFileSizeAsync();
                healthCheckResults.Add(fileSizeResult);
                data["DatabaseSize"] = fileSizeResult.Status;
                data["DatabaseSizeDetails"] = fileSizeResult.Details;

                // Determine overall health
                var unhealthyCount = healthCheckResults.Count(r => r.Status == "Unhealthy");
                var degradedCount = healthCheckResults.Count(r => r.Status == "Degraded");

                if (unhealthyCount > 0)
                {
                    return HealthCheckResult.Unhealthy(
                        $"Database health check failed: {unhealthyCount} unhealthy checks",
                        data: data);
                }

                if (degradedCount > 0)
                {
                    return HealthCheckResult.Degraded(
                        $"Database performance degraded: {degradedCount} degraded checks",
                        data: data);
                }

                return HealthCheckResult.Healthy(
                    "Database is healthy",
                    data: data);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Database health check failed with exception");
                
                return HealthCheckResult.Unhealthy(
                    $"Database health check failed: {ex.Message}",
                    exception: ex,
                    data: data);
            }
        }

        private async Task<HealthCheckItem> CheckDatabaseConnectionAsync(CancellationToken cancellationToken)
        {
            try
            {
                var stopwatch = Stopwatch.StartNew();
                var canConnect = await _dbContext.Database.CanConnectAsync(cancellationToken);
                stopwatch.Stop();

                if (canConnect)
                {
                    return new HealthCheckItem
                    {
                        Name = "DatabaseConnection",
                        Status = "Healthy",
                        Message = $"Connected successfully in {stopwatch.ElapsedMilliseconds}ms"
                    };
                }

                return new HealthCheckItem
                {
                    Name = "DatabaseConnection",
                    Status = "Unhealthy",
                    Message = "Cannot connect to database"
                };
            }
            catch (Exception ex)
            {
                return new HealthCheckItem
                {
                    Name = "DatabaseConnection",
                    Status = "Unhealthy",
                    Message = $"Connection failed: {ex.Message}"
                };
            }
        }

        private async Task<HealthCheckItem> CheckMigrationStatusAsync(CancellationToken cancellationToken)
        {
            try
            {
                var pendingMigrations = await _dbContext.Database
                    .GetPendingMigrationsAsync(cancellationToken);

                var pendingCount = pendingMigrations.Count();

                if (pendingCount == 0)
                {
                    var appliedMigrations = await _dbContext.Database
                        .GetAppliedMigrationsAsync(cancellationToken);

                    return new HealthCheckItem
                    {
                        Name = "MigrationStatus",
                        Status = "Healthy",
                        Message = $"All migrations applied. Total: {appliedMigrations.Count()}"
                    };
                }

                return new HealthCheckItem
                {
                    Name = "MigrationStatus",
                    Status = "Degraded",
                    Message = $"{pendingCount} pending migrations found"
                };
            }
            catch (Exception ex)
            {
                return new HealthCheckItem
                {
                    Name = "MigrationStatus",
                    Status = "Unhealthy",
                    Message = $"Migration check failed: {ex.Message}"
                };
            }
        }

        private async Task<HealthCheckItem> CheckDiskSpaceAsync()
        {
            try
            {
                var connectionString = _configuration.GetConnectionString("DefaultConnection");
                var dataSource = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(connectionString).DataSource;
                
                if (string.IsNullOrEmpty(dataSource))
                {
                    return new HealthCheckItem
                    {
                        Name = "DiskSpace",
                        Status = "Unhealthy",
                        Message = "Cannot determine database file location"
                    };
                }

                var fileInfo = new FileInfo(dataSource);
                var driveInfo = new DriveInfo(fileInfo.Directory.Root.FullName);
                
                var freeSpaceGB = driveInfo.AvailableFreeSpace / (1024.0 * 1024.0 * 1024.0);
                var totalSpaceGB = driveInfo.TotalSize / (1024.0 * 1024.0 * 1024.0);
                var usedPercentage = ((totalSpaceGB - freeSpaceGB) / totalSpaceGB) * 100;

                var warningThresholdGB = _configuration.GetValue<double>("HealthChecks:DiskSpaceWarningGB", 10.0);
                var criticalThresholdGB = _configuration.GetValue<double>("HealthChecks:DiskSpaceCriticalGB", 5.0);

                var details = new Dictionary<string, object>
                {
                    { "FreeSpaceGB", Math.Round(freeSpaceGB, 2) },
                    { "TotalSpaceGB", Math.Round(totalSpaceGB, 2) },
                    { "UsedPercentage", Math.Round(usedPercentage, 2) }
                };

                if (freeSpaceGB < criticalThresholdGB)
                {
                    return new HealthCheckItem
                    {
                        Name = "DiskSpace",
                        Status = "Unhealthy",
                        Message = $"Critical: Only {freeSpaceGB:F2}GB free space remaining",
                        Details = details
                    };
                }

                if (freeSpaceGB < warningThresholdGB)
                {
                    return new HealthCheckItem
                    {
                        Name = "DiskSpace",
                        Status = "Degraded",
                        Message = $"Warning: Only {freeSpaceGB:F2}GB free space remaining",
                        Details = details
                    };
                }

                return new HealthCheckItem
                {
                    Name = "DiskSpace",
                    Status = "Healthy",
                    Message = $"Sufficient disk space: {freeSpaceGB:F2}GB free",
                    Details = details
                };
            }
            catch (Exception ex)
            {
                return new HealthCheckItem
                {
                    Name = "DiskSpace",
                    Status = "Unhealthy",
                    Message = $"Disk space check failed: {ex.Message}"
                };
            }
        }

        private async Task<HealthCheckItem> CheckTablesAsync(CancellationToken cancellationToken)
        {
            try
            {
                var requiredTables = new[] { "Analyses", "Rules", "Parsers", "IOCs", "MITREs" };
                var existingTables = new List<string>();
                var missingTables = new List<string>();

                foreach (var table in requiredTables)
                {
                    var sql = $"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='{table}'";
                    var exists = await _dbContext.Database
                        .ExecuteSqlRawAsync(sql, cancellationToken) > 0;

                    if (exists)
                    {
                        existingTables.Add(table);
                    }
                    else
                    {
                        missingTables.Add(table);
                    }
                }

                var details = new Dictionary<string, object>
                {
                    { "ExistingTables", existingTables },
                    { "MissingTables", missingTables }
                };

                if (missingTables.Count == 0)
                {
                    return new HealthCheckItem
                    {
                        Name = "TableExistence",
                        Status = "Healthy",
                        Message = "All required tables exist",
                        Details = details
                    };
                }

                return new HealthCheckItem
                {
                    Name = "TableExistence",
                    Status = "Unhealthy",
                    Message = $"Missing {missingTables.Count} required tables",
                    Details = details
                };
            }
            catch (Exception ex)
            {
                return new HealthCheckItem
                {
                    Name = "TableExistence",
                    Status = "Unhealthy",
                    Message = $"Table check failed: {ex.Message}"
                };
            }
        }

        private async Task<HealthCheckItem> CheckQueryPerformanceAsync(CancellationToken cancellationToken)
        {
            try
            {
                var stopwatch = Stopwatch.StartNew();
                
                // Simple query to test performance
                var count = await _dbContext.Analyses
                    .Where(a => a.CreatedAt > DateTime.UtcNow.AddDays(-30))
                    .CountAsync(cancellationToken);

                stopwatch.Stop();

                var performanceThresholdMs = _configuration.GetValue<int>("HealthChecks:QueryPerformanceThresholdMs", 100);
                var criticalThresholdMs = _configuration.GetValue<int>("HealthChecks:QueryPerformanceCriticalMs", 500);

                var details = new Dictionary<string, object>
                {
                    { "ElapsedMs", stopwatch.ElapsedMilliseconds },
                    { "RecordCount", count }
                };

                if (stopwatch.ElapsedMilliseconds > criticalThresholdMs)
                {
                    return new HealthCheckItem
                    {
                        Name = "QueryPerformance",
                        Status = "Unhealthy",
                        Message = $"Query performance critical: {stopwatch.ElapsedMilliseconds}ms",
                        Details = details
                    };
                }

                if (stopwatch.ElapsedMilliseconds > performanceThresholdMs)
                {
                    return new HealthCheckItem
                    {
                        Name = "QueryPerformance",
                        Status = "Degraded",
                        Message = $"Query performance degraded: {stopwatch.ElapsedMilliseconds}ms",
                        Details = details
                    };
                }

                return new HealthCheckItem
                {
                    Name = "QueryPerformance",
                    Status = "Healthy",
                    Message = $"Query performance good: {stopwatch.ElapsedMilliseconds}ms",
                    Details = details
                };
            }
            catch (Exception ex)
            {
                return new HealthCheckItem
                {
                    Name = "QueryPerformance",
                    Status = "Unhealthy",
                    Message = $"Performance test failed: {ex.Message}"
                };
            }
        }

        private async Task<HealthCheckItem> CheckDatabaseFileSizeAsync()
        {
            try
            {
                var connectionString = _configuration.GetConnectionString("DefaultConnection");
                var dataSource = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(connectionString).DataSource;
                
                if (!File.Exists(dataSource))
                {
                    return new HealthCheckItem
                    {
                        Name = "DatabaseFileSize",
                        Status = "Unhealthy",
                        Message = "Database file not found"
                    };
                }

                var fileInfo = new FileInfo(dataSource);
                var fileSizeMB = fileInfo.Length / (1024.0 * 1024.0);
                
                var warningSizeMB = _configuration.GetValue<double>("HealthChecks:DatabaseSizeWarningMB", 1024.0); // 1GB
                var criticalSizeMB = _configuration.GetValue<double>("HealthChecks:DatabaseSizeCriticalMB", 5120.0); // 5GB

                var details = new Dictionary<string, object>
                {
                    { "FileSizeMB", Math.Round(fileSizeMB, 2) },
                    { "FilePath", dataSource },
                    { "LastModified", fileInfo.LastWriteTimeUtc }
                };

                if (fileSizeMB > criticalSizeMB)
                {
                    return new HealthCheckItem
                    {
                        Name = "DatabaseFileSize",
                        Status = "Unhealthy",
                        Message = $"Database file critically large: {fileSizeMB:F2}MB",
                        Details = details
                    };
                }

                if (fileSizeMB > warningSizeMB)
                {
                    return new HealthCheckItem
                    {
                        Name = "DatabaseFileSize",
                        Status = "Degraded",
                        Message = $"Database file size warning: {fileSizeMB:F2}MB",
                        Details = details
                    };
                }

                return new HealthCheckItem
                {
                    Name = "DatabaseFileSize",
                    Status = "Healthy",
                    Message = $"Database file size normal: {fileSizeMB:F2}MB",
                    Details = details
                };
            }
            catch (Exception ex)
            {
                return new HealthCheckItem
                {
                    Name = "DatabaseFileSize",
                    Status = "Unhealthy",
                    Message = $"File size check failed: {ex.Message}"
                };
            }
        }

        private class HealthCheckItem
        {
            public string Name { get; set; }
            public string Status { get; set; }
            public string Message { get; set; }
            public Dictionary<string, object> Details { get; set; } = new();
        }
    }
}