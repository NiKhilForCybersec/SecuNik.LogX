using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecuNikLogX.API.Hubs;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SecuNikLogX.API.Services
{
    public class BackgroundJobService : BackgroundService, IDisposable
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IHubContext<AnalysisHub, IAnalysisHubClient> _hubContext;
        private readonly ILogger<BackgroundJobService> _logger;
        private readonly IConfiguration _configuration;
        private readonly ConcurrentQueue<Job> _jobQueue = new();
        private readonly SemaphoreSlim _jobSemaphore;
        private readonly List<Task> _workerTasks = new();
        private CancellationTokenSource _shutdownTokenSource;
        private readonly Timer _maintenanceTimer;
        private readonly object _statsLock = new();
        private readonly JobStatistics _statistics = new();

        public BackgroundJobService(
            IServiceProvider serviceProvider,
            IHubContext<AnalysisHub, IAnalysisHubClient> hubContext,
            ILogger<BackgroundJobService> logger,
            IConfiguration configuration)
        {
            _serviceProvider = serviceProvider;
            _hubContext = hubContext;
            _logger = logger;
            _configuration = configuration;

            var workerCount = _configuration.GetValue<int>("BackgroundJobs:WorkerCount", 4);
            _jobSemaphore = new SemaphoreSlim(0, int.MaxValue);

            // Start maintenance timer for cleanup tasks
            _maintenanceTimer = new Timer(
                PerformMaintenance,
                null,
                TimeSpan.FromMinutes(5),
                TimeSpan.FromMinutes(30));

            _logger.LogInformation("BackgroundJobService initialized with {WorkerCount} workers", workerCount);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _shutdownTokenSource = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);

            var workerCount = _configuration.GetValue<int>("BackgroundJobs:WorkerCount", 4);
            var queueCapacity = _configuration.GetValue<int>("BackgroundJobs:QueueCapacity", 1000);

            _logger.LogInformation("Starting {WorkerCount} background job workers", workerCount);

            // Start worker tasks
            for (int i = 0; i < workerCount; i++)
            {
                var workerId = i;
                var workerTask = Task.Run(async () => await ProcessJobsAsync(workerId, _shutdownTokenSource.Token));
                _workerTasks.Add(workerTask);
            }

            // Monitor queue size
            _ = Task.Run(async () => await MonitorQueueAsync(_shutdownTokenSource.Token));

            // Wait for shutdown
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }

        public async Task<string> EnqueueJobAsync(Job job)
        {
            var queueCapacity = _configuration.GetValue<int>("BackgroundJobs:QueueCapacity", 1000);

            if (_jobQueue.Count >= queueCapacity)
            {
                _logger.LogWarning("Job queue is full. Rejecting job: {JobType}", job.Type);
                throw new InvalidOperationException($"Job queue is full (capacity: {queueCapacity})");
            }

            job.Id = Guid.NewGuid().ToString();
            job.CreatedAt = DateTime.UtcNow;
            job.Status = JobStatus.Queued;

            _jobQueue.Enqueue(job);
            _jobSemaphore.Release();

            lock (_statsLock)
            {
                _statistics.TotalQueued++;
            }

            _logger.LogInformation("Job {JobId} of type {JobType} enqueued", job.Id, job.Type);

            return job.Id;
        }

        private async Task ProcessJobsAsync(int workerId, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Worker {WorkerId} started", workerId);

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Wait for job
                    await _jobSemaphore.WaitAsync(cancellationToken);

                    if (_jobQueue.TryDequeue(out var job))
                    {
                        await ProcessJobAsync(job, workerId, cancellationToken);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Worker {WorkerId} encountered an error", workerId);
                    await Task.Delay(1000, cancellationToken);
                }
            }

            _logger.LogInformation("Worker {WorkerId} stopped", workerId);
        }

        private async Task ProcessJobAsync(Job job, int workerId, CancellationToken cancellationToken)
        {
            var jobTimeout = _configuration.GetValue<TimeSpan>("BackgroundJobs:JobTimeout", TimeSpan.FromMinutes(30));
            using var jobCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            jobCts.CancelAfter(jobTimeout);

            job.StartedAt = DateTime.UtcNow;
            job.Status = JobStatus.Running;
            job.WorkerId = workerId;

            _logger.LogInformation("Worker {WorkerId} processing job {JobId} of type {JobType}", 
                workerId, job.Id, job.Type);

            lock (_statsLock)
            {
                _statistics.TotalProcessing++;
            }

            try
            {
                switch (job.Type)
                {
                    case JobType.AnalysisJob:
                        await ProcessAnalysisJobAsync(job, jobCts.Token);
                        break;

                    case JobType.BatchAnalysisJob:
                        await ProcessBatchAnalysisJobAsync(job, jobCts.Token);
                        break;

                    case JobType.ReportGenerationJob:
                        await ProcessReportGenerationJobAsync(job, jobCts.Token);
                        break;

                    case JobType.MaintenanceJob:
                        await ProcessMaintenanceJobAsync(job, jobCts.Token);
                        break;

                    default:
                        throw new NotSupportedException($"Job type {job.Type} is not supported");
                }

                job.CompletedAt = DateTime.UtcNow;
                job.Status = JobStatus.Completed;

                lock (_statsLock)
                {
                    _statistics.TotalCompleted++;
                    _statistics.TotalProcessing--;
                }

                _logger.LogInformation("Job {JobId} completed successfully by worker {WorkerId}", 
                    job.Id, workerId);
            }
            catch (OperationCanceledException)
            {
                job.Status = JobStatus.Cancelled;
                job.Error = "Job was cancelled due to timeout or shutdown";

                lock (_statsLock)
                {
                    _statistics.TotalCancelled++;
                    _statistics.TotalProcessing--;
                }

                _logger.LogWarning("Job {JobId} was cancelled", job.Id);
            }
            catch (Exception ex)
            {
                job.Status = JobStatus.Failed;
                job.Error = ex.Message;
                job.FailedAt = DateTime.UtcNow;

                lock (_statsLock)
                {
                    _statistics.TotalFailed++;
                    _statistics.TotalProcessing--;
                }

                _logger.LogError(ex, "Job {JobId} failed", job.Id);

                // Retry logic
                var retryCount = _configuration.GetValue<int>("BackgroundJobs:RetryCount", 3);
                if (job.RetryCount < retryCount)
                {
                    job.RetryCount++;
                    job.Status = JobStatus.Queued;
                    job.ScheduledRetryAt = DateTime.UtcNow.AddMinutes(Math.Pow(2, job.RetryCount));
                    
                    _jobQueue.Enqueue(job);
                    _jobSemaphore.Release();

                    _logger.LogInformation("Job {JobId} scheduled for retry #{RetryCount}", 
                        job.Id, job.RetryCount);
                }
            }
        }

        private async Task ProcessAnalysisJobAsync(Job job, CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            var fileProcessingService = scope.ServiceProvider.GetRequiredService<FileProcessingService>();

            var analysisId = job.Data["AnalysisId"] as Guid? ?? Guid.Empty;
            var filePath = job.Data["FilePath"] as string;

            if (analysisId == Guid.Empty || string.IsNullOrEmpty(filePath))
            {
                throw new ArgumentException("Invalid job data for AnalysisJob");
            }

            await fileProcessingService.ProcessFileAsync(analysisId, filePath);
        }

        private async Task ProcessBatchAnalysisJobAsync(Job job, CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            var fileProcessingService = scope.ServiceProvider.GetRequiredService<FileProcessingService>();

            var batchId = job.Data["BatchId"] as string;
            var filePaths = job.Data["FilePaths"] as List<string> ?? new List<string>();

            _logger.LogInformation("Processing batch analysis {BatchId} with {FileCount} files", 
                batchId, filePaths.Count);

            var tasks = new List<Task<ProcessingResult>>();

            foreach (var filePath in filePaths)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                var analysisId = Guid.NewGuid();
                tasks.Add(fileProcessingService.ProcessFileAsync(analysisId, filePath));

                // Limit concurrent processing
                if (tasks.Count >= 5)
                {
                    var completed = await Task.WhenAny(tasks);
                    tasks.Remove(completed);
                }
            }

            // Wait for remaining tasks
            await Task.WhenAll(tasks);

            _logger.LogInformation("Batch analysis {BatchId} completed", batchId);
        }

        private async Task ProcessReportGenerationJobAsync(Job job, CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            var analysisService = scope.ServiceProvider.GetRequiredService<Core.Interfaces.IAnalysisService>();

            var analysisId = job.Data["AnalysisId"] as Guid? ?? Guid.Empty;
            var reportType = job.Data["ReportType"] as string ?? "Standard";

            _logger.LogInformation("Generating {ReportType} report for analysis {AnalysisId}", 
                reportType, analysisId);

            // Simulate report generation
            await Task.Delay(5000, cancellationToken);

            // Notify completion
            if (job.Data.ContainsKey("NotificationGroup"))
            {
                var group = job.Data["NotificationGroup"] as string;
                await _hubContext.Clients.Group(group)
                    .ReceiveAnalysisProgress(analysisId.ToString(), 100, $"{reportType} report generated");
            }
        }

        private async Task ProcessMaintenanceJobAsync(Job job, CancellationToken cancellationToken)
        {
            var maintenanceType = job.Data["Type"] as string ?? "General";

            _logger.LogInformation("Running maintenance job: {MaintenanceType}", maintenanceType);

            switch (maintenanceType)
            {
                case "CleanupOldAnalyses":
                    await CleanupOldAnalysesAsync(cancellationToken);
                    break;

                case "OptimizeDatabase":
                    await OptimizeDatabaseAsync(cancellationToken);
                    break;

                case "CleanupTempFiles":
                    await CleanupTempFilesAsync(cancellationToken);
                    break;

                default:
                    _logger.LogWarning("Unknown maintenance type: {MaintenanceType}", maintenanceType);
                    break;
            }
        }

        private async Task CleanupOldAnalysesAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<Data.ApplicationDbContext>();

            var cutoffDate = DateTime.UtcNow.AddDays(-30);
            var oldAnalyses = dbContext.Analyses
                .Where(a => a.CreatedAt < cutoffDate && a.Status == Models.AnalysisStatus.Completed)
                .Take(100);

            await dbContext.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Cleaned up old analyses");
        }

        private async Task OptimizeDatabaseAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<Data.ApplicationDbContext>();

            // SQLite optimization
            await dbContext.Database.ExecuteSqlRawAsync("VACUUM;", cancellationToken);
            await dbContext.Database.ExecuteSqlRawAsync("ANALYZE;", cancellationToken);

            _logger.LogInformation("Database optimization completed");
        }

        private async Task CleanupTempFilesAsync(CancellationToken cancellationToken)
        {
            var tempPath = _configuration.GetValue<string>("FileStorage:TempPath", "./temp/");
            if (System.IO.Directory.Exists(tempPath))
            {
                var cutoffDate = DateTime.UtcNow.AddHours(-24);
                var tempFiles = System.IO.Directory.GetFiles(tempPath)
                    .Where(f => System.IO.File.GetCreationTimeUtc(f) < cutoffDate);

                foreach (var file in tempFiles)
                {
                    try
                    {
                        System.IO.File.Delete(file);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to delete temp file: {FilePath}", file);
                    }
                }
            }

            await Task.CompletedTask;
        }

        private async Task MonitorQueueAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    lock (_statsLock)
                    {
                        _logger.LogInformation(
                            "Job queue status - Queued: {Queued}, Processing: {Processing}, " +
                            "Completed: {Completed}, Failed: {Failed}, Cancelled: {Cancelled}",
                            _jobQueue.Count,
                            _statistics.TotalProcessing,
                            _statistics.TotalCompleted,
                            _statistics.TotalFailed,
                            _statistics.TotalCancelled);
                    }

                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        private void PerformMaintenance(object state)
        {
            try
            {
                _logger.LogInformation("Performing scheduled maintenance");

                // Enqueue maintenance jobs
                var maintenanceJobs = new[]
                {
                    new Job
                    {
                        Type = JobType.MaintenanceJob,
                        Data = new Dictionary<string, object> { { "Type", "CleanupOldAnalyses" } }
                    },
                    new Job
                    {
                        Type = JobType.MaintenanceJob,
                        Data = new Dictionary<string, object> { { "Type", "CleanupTempFiles" } }
                    }
                };

                foreach (var job in maintenanceJobs)
                {
                    _ = EnqueueJobAsync(job).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during scheduled maintenance");
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("BackgroundJobService is stopping");

            _maintenanceTimer?.Change(Timeout.Infinite, 0);
            _shutdownTokenSource?.Cancel();

            // Wait for workers to complete
            await Task.WhenAll(_workerTasks);

            await base.StopAsync(cancellationToken);
        }

        public override void Dispose()
        {
            _maintenanceTimer?.Dispose();
            _jobSemaphore?.Dispose();
            _shutdownTokenSource?.Dispose();
            base.Dispose();
        }
    }

    public class Job
    {
        public string Id { get; set; }
        public JobType Type { get; set; }
        public Dictionary<string, object> Data { get; set; } = new();
        public JobStatus Status { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? StartedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        public DateTime? FailedAt { get; set; }
        public DateTime? ScheduledRetryAt { get; set; }
        public int RetryCount { get; set; }
        public int? WorkerId { get; set; }
        public string Error { get; set; }
    }

    public enum JobType
    {
        AnalysisJob,
        BatchAnalysisJob,
        ReportGenerationJob,
        MaintenanceJob
    }

    public enum JobStatus
    {
        Queued,
        Running,
        Completed,
        Failed,
        Cancelled
    }

    public class JobStatistics
    {
        public int TotalQueued { get; set; }
        public int TotalProcessing { get; set; }
        public int TotalCompleted { get; set; }
        public int TotalFailed { get; set; }
        public int TotalCancelled { get; set; }
    }
}