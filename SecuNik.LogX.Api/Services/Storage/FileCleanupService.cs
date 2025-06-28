using SecuNik.LogX.Core.Configuration;
using SecuNik.LogX.Core.Interfaces;
using Microsoft.Extensions.Options;

namespace SecuNik.LogX.Api.Services.Storage
{
    public class FileCleanupService : BackgroundService
    {
        private readonly IStorageService _storageService;
        private readonly StorageOptions _storageOptions;
        private readonly ILogger<FileCleanupService> _logger;

        public FileCleanupService(
            IStorageService storageService,
            IOptions<StorageOptions> storageOptions,
            ILogger<FileCleanupService> logger)
        {
            _storageService = storageService;
            _storageOptions = storageOptions.Value;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            if (!_storageOptions.EnableAutoCleanup)
            {
                _logger.LogInformation("Automatic file cleanup is disabled");
                return;
            }

            _logger.LogInformation("File cleanup service started. Cleanup interval: {CleanupInterval} hours",
                _storageOptions.CleanupIntervalHours);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await PerformCleanupAsync(stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during file cleanup");
                }

                // Wait for the next cleanup interval
                var interval = TimeSpan.FromHours(_storageOptions.CleanupIntervalHours);
                _logger.LogInformation("Next cleanup scheduled in {Interval}", interval);
                await Task.Delay(interval, stoppingToken);
            }
        }

        private async Task PerformCleanupAsync(CancellationToken cancellationToken)
        {
            try
            {
                _logger.LogInformation("Starting file cleanup");

                // Get current storage info
                var storageInfo = await _storageService.GetStorageInfoAsync(cancellationToken);
                _logger.LogInformation("Current storage usage: {UsedSpace}/{TotalSpace} bytes ({UsagePercentage}%)",
                    storageInfo.UsedSpace, storageInfo.TotalSpace,
                    storageInfo.TotalSpace > 0 ? (storageInfo.UsedSpace * 100.0 / storageInfo.TotalSpace).ToString("F2") : "0");

                // Check if we need to clean up based on storage usage
                var usagePercentage = storageInfo.TotalSpace > 0 ? (double)storageInfo.UsedSpace / storageInfo.TotalSpace : 0;
                var maxAge = TimeSpan.FromDays(_storageOptions.RetentionDays);

                if (usagePercentage > 0.9) // 90% usage
                {
                    _logger.LogWarning("Storage usage is high (>90%). Performing aggressive cleanup");
                    maxAge = TimeSpan.FromDays(_storageOptions.RetentionDays / 2); // Half the retention period
                }
                else if (usagePercentage > 0.8) // 80% usage
                {
                    _logger.LogInformation("Storage usage is moderate (>80%). Performing standard cleanup");
                }
                else
                {
                    _logger.LogInformation("Storage usage is normal. Performing routine cleanup");
                }

                // Perform the cleanup
                await _storageService.CleanupOldFilesAsync(maxAge, cancellationToken);

                // Get updated storage info
                var updatedStorageInfo = await _storageService.GetStorageInfoAsync(cancellationToken);
                var spaceFreed = storageInfo.UsedSpace - updatedStorageInfo.UsedSpace;

                _logger.LogInformation("Cleanup completed. Freed {SpaceFreed} bytes. New usage: {UsedSpace}/{TotalSpace} bytes ({UsagePercentage}%)",
                    spaceFreed, updatedStorageInfo.UsedSpace, updatedStorageInfo.TotalSpace,
                    updatedStorageInfo.TotalSpace > 0 ? (updatedStorageInfo.UsedSpace * 100.0 / updatedStorageInfo.TotalSpace).ToString("F2") : "0");

                // Update last cleanup marker
                await UpdateLastCleanupMarkerAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error performing file cleanup");
                throw;
            }
        }

        private async Task UpdateLastCleanupMarkerAsync()
        {
            try
            {
                var markerFile = Path.Combine(_storageOptions.BasePath, "last_cleanup.txt");
                await File.WriteAllTextAsync(markerFile, DateTime.UtcNow.ToString("o"));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error updating last cleanup marker");
            }
        }
    }
}