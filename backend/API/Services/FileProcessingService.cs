using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecuNikLogX.API.Data;
using SecuNikLogX.API.Hubs;
using SecuNikLogX.API.Models;
using SecuNikLogX.Core.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecuNikLogX.API.Services
{
    public class FileProcessingService
    {
        private readonly IAnalysisService _analysisService;
        private readonly AIService _aiService;
        private readonly IOCExtractor _iocExtractor;
        private readonly MITREMapper _mitreMapper;
        private readonly IHubContext<AnalysisHub, IAnalysisHubClient> _hubContext;
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<FileProcessingService> _logger;
        private readonly IConfiguration _configuration;

        // Magic number signatures for common file types
        private static readonly Dictionary<string, byte[]> _magicNumbers = new()
        {
            { ".exe", new byte[] { 0x4D, 0x5A } }, // MZ
            { ".dll", new byte[] { 0x4D, 0x5A } }, // MZ
            { ".pdf", new byte[] { 0x25, 0x50, 0x44, 0x46 } }, // %PDF
            { ".zip", new byte[] { 0x50, 0x4B, 0x03, 0x04 } }, // PK
            { ".png", new byte[] { 0x89, 0x50, 0x4E, 0x47 } }, // PNG
            { ".jpg", new byte[] { 0xFF, 0xD8, 0xFF } }, // JPEG
            { ".doc", new byte[] { 0xD0, 0xCF, 0x11, 0xE0 } }, // DOC
            { ".docx", new byte[] { 0x50, 0x4B, 0x03, 0x04 } }, // DOCX (ZIP)
            { ".txt", new byte[] { } }, // Text files have no magic number
            { ".log", new byte[] { } }, // Log files have no magic number
            { ".evtx", new byte[] { 0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65 } } // Windows Event Log
        };

        public FileProcessingService(
            IAnalysisService analysisService,
            AIService aiService,
            IOCExtractor iocExtractor,
            MITREMapper mitreMapper,
            IHubContext<AnalysisHub, IAnalysisHubClient> hubContext,
            ApplicationDbContext dbContext,
            ILogger<FileProcessingService> logger,
            IConfiguration configuration)
        {
            _analysisService = analysisService;
            _aiService = aiService;
            _iocExtractor = iocExtractor;
            _mitreMapper = mitreMapper;
            _hubContext = hubContext;
            _dbContext = dbContext;
            _logger = logger;
            _configuration = configuration;
        }

        public async Task<ProcessingResult> ProcessFileAsync(Guid analysisId, string filePath)
        {
            try
            {
                _logger.LogInformation("Starting file processing for analysis {AnalysisId}, file: {FilePath}", 
                    analysisId, filePath);

                // Validate file
                var validationResult = await ValidateFileAsync(filePath);
                if (!validationResult.IsValid)
                {
                    await SendProgressUpdate(analysisId, 0, $"File validation failed: {validationResult.Message}");
                    return new ProcessingResult
                    {
                        Success = false,
                        Message = validationResult.Message,
                        AnalysisId = analysisId
                    };
                }

                // Start processing
                await SendProgressUpdate(analysisId, 10, "File validated, starting analysis");

                // Determine if large file processing is needed
                var fileInfo = new FileInfo(filePath);
                var maxFileSize = _configuration.GetValue<long>("FileProcessing:MaxDirectProcessingSize", 104857600); // 100MB

                if (fileInfo.Length > maxFileSize)
                {
                    return await ProcessLargeFileAsync(filePath);
                }

                // Regular file processing
                await SendProgressUpdate(analysisId, 20, "Reading file content");
                var content = await File.ReadAllTextAsync(filePath);

                // Extract IOCs
                await SendProgressUpdate(analysisId, 30, "Extracting indicators of compromise");
                var iocExtractionOptions = new IOCExtractionOptions
                {
                    AnalysisId = analysisId,
                    EnableContextExtraction = true,
                    ContextWindowSize = 100
                };
                var extractedIOCs = await _iocExtractor.ExtractIOCsAsync(content, iocExtractionOptions);

                // Notify about IOCs in real-time
                foreach (var ioc in extractedIOCs)
                {
                    var notification = new IOCNotification
                    {
                        Id = Guid.NewGuid().ToString(),
                        Type = ioc.Type.ToString(),
                        Value = ioc.Value,
                        Context = ioc.Context,
                        Confidence = ioc.Confidence,
                        DetectedAt = DateTime.UtcNow,
                        Severity = CalculateSeverity(ioc),
                        Metadata = new Dictionary<string, object>
                        {
                            { "Source", Path.GetFileName(filePath) },
                            { "Offset", ioc.Offset }
                        }
                    };

                    await _hubContext.Clients.Group($"analysis-{analysisId}")
                        .ReceiveIOCDetected(analysisId.ToString(), notification);
                }

                await SendProgressUpdate(analysisId, 50, "Mapping to MITRE ATT&CK framework");

                // MITRE mapping
                var mitreAnalysisOptions = new MITREAnalysisOptions
                {
                    AnalysisId = analysisId,
                    IOCs = extractedIOCs
                };
                var mitreTechniques = await _mitreMapper.AnalyzeAsync(mitreAnalysisOptions);

                // Notify about MITRE techniques
                foreach (var technique in mitreTechniques)
                {
                    var notification = new MITRENotification
                    {
                        TechniqueId = technique.TechniqueId,
                        Name = technique.Name,
                        Tactic = technique.Tactic,
                        Confidence = technique.Confidence,
                        Description = technique.Description,
                        RelatedIOCs = technique.RelatedIOCs.Select(i => i.Value).ToList(),
                        MappedAt = DateTime.UtcNow
                    };

                    await _hubContext.Clients.Group($"analysis-{analysisId}")
                        .ReceiveMITREMapped(analysisId.ToString(), notification);
                }

                await SendProgressUpdate(analysisId, 70, "Performing AI-powered analysis");

                // AI analysis
                var aiOptions = new AIAnalysisOptions
                {
                    AnalysisType = AIAnalysisType.Comprehensive,
                    Model = AIModel.GPT4,
                    MaxTokens = 2000,
                    Temperature = 0.3
                };
                var aiResult = await _aiService.AnalyzeWithAIAsync(content, aiOptions);

                await SendProgressUpdate(analysisId, 90, "Finalizing analysis results");

                // Update analysis record
                var analysis = await _dbContext.Analyses.FindAsync(analysisId);
                if (analysis != null)
                {
                    analysis.Status = AnalysisStatus.Completed;
                    analysis.CompletedAt = DateTime.UtcNow;
                    analysis.ThreatLevel = CalculateThreatLevel(extractedIOCs, mitreTechniques);
                    analysis.IOCCount = extractedIOCs.Count;
                    analysis.MITRECount = mitreTechniques.Count;
                    analysis.AIInsights = aiResult.Summary;

                    await _dbContext.SaveChangesAsync();
                }

                // Send completion notification
                var completeNotification = new AnalysisCompleteNotification
                {
                    AnalysisId = analysisId.ToString(),
                    Status = "Completed",
                    CompletedAt = DateTime.UtcNow,
                    TotalIOCs = extractedIOCs.Count,
                    TotalMITRETechniques = mitreTechniques.Count,
                    ThreatLevel = analysis?.ThreatLevel ?? 0.0,
                    Summary = aiResult.Summary,
                    Statistics = new Dictionary<string, object>
                    {
                        { "FileSize", fileInfo.Length },
                        { "ProcessingTime", (DateTime.UtcNow - (analysis?.CreatedAt ?? DateTime.UtcNow)).TotalSeconds },
                        { "UniqueIOCTypes", extractedIOCs.Select(i => i.Type).Distinct().Count() },
                        { "HighConfidenceIOCs", extractedIOCs.Count(i => i.Confidence > 0.8) }
                    }
                };

                await _hubContext.Clients.Group($"analysis-{analysisId}")
                    .ReceiveAnalysisComplete(analysisId.ToString(), completeNotification);

                await SendProgressUpdate(analysisId, 100, "Analysis completed successfully");

                return new ProcessingResult
                {
                    Success = true,
                    Message = "File processed successfully",
                    AnalysisId = analysisId,
                    IOCCount = extractedIOCs.Count,
                    MITRECount = mitreTechniques.Count,
                    ThreatLevel = analysis?.ThreatLevel ?? 0.0
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing file for analysis {AnalysisId}", analysisId);
                await SendProgressUpdate(analysisId, 0, $"Processing error: {ex.Message}");

                await _hubContext.Clients.Group($"analysis-{analysisId}")
                    .ReceiveError(ex.Message, "PROCESSING_ERROR");

                return new ProcessingResult
                {
                    Success = false,
                    Message = $"Processing failed: {ex.Message}",
                    AnalysisId = analysisId
                };
            }
        }

        public async Task<FileValidationResult> ValidateFileAsync(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    return new FileValidationResult
                    {
                        IsValid = false,
                        Message = "File does not exist"
                    };
                }

                var fileInfo = new FileInfo(filePath);
                var maxFileSize = _configuration.GetValue<long>("FileProcessing:MaxFileSize", 5368709120); // 5GB

                if (fileInfo.Length > maxFileSize)
                {
                    return new FileValidationResult
                    {
                        IsValid = false,
                        Message = $"File size exceeds maximum allowed size of {maxFileSize / (1024 * 1024 * 1024)}GB"
                    };
                }

                // Check file extension
                var allowedExtensions = _configuration.GetSection("FileProcessing:AllowedExtensions")
                    .Get<string[]>() ?? new[] { ".txt", ".log", ".csv", ".json", ".xml", ".evtx", ".pdf", ".doc", ".docx" };

                var extension = Path.GetExtension(filePath).ToLowerInvariant();
                if (!allowedExtensions.Contains(extension))
                {
                    return new FileValidationResult
                    {
                        IsValid = false,
                        Message = $"File type '{extension}' is not allowed"
                    };
                }

                // Validate magic number
                if (_magicNumbers.ContainsKey(extension))
                {
                    var expectedMagic = _magicNumbers[extension];
                    if (expectedMagic.Length > 0)
                    {
                        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                        var buffer = new byte[expectedMagic.Length];
                        await fs.ReadAsync(buffer, 0, buffer.Length);

                        if (!buffer.SequenceEqual(expectedMagic))
                        {
                            return new FileValidationResult
                            {
                                IsValid = false,
                                Message = "File content does not match expected format"
                            };
                        }
                    }
                }

                // Scan for malware signatures if enabled
                if (_configuration.GetValue<bool>("FileProcessing:EnableMalwareScan", true))
                {
                    var scanResult = await ScanForMalwareAsync(filePath);
                    if (!scanResult.IsClean)
                    {
                        await QuarantineFileAsync(filePath, scanResult.Reason);
                        return new FileValidationResult
                        {
                            IsValid = false,
                            Message = $"File quarantined: {scanResult.Reason}"
                        };
                    }
                }

                return new FileValidationResult
                {
                    IsValid = true,
                    Message = "File validation successful"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating file: {FilePath}", filePath);
                return new FileValidationResult
                {
                    IsValid = false,
                    Message = $"Validation error: {ex.Message}"
                };
            }
        }

        public async Task<QuarantineResult> QuarantineFileAsync(string filePath, string reason)
        {
            try
            {
                var quarantineDir = _configuration.GetValue<string>("FileProcessing:QuarantinePath", "./quarantine/");
                Directory.CreateDirectory(quarantineDir);

                var fileName = Path.GetFileName(filePath);
                var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
                var quarantineName = $"{timestamp}_{fileName}.quarantine";
                var quarantinePath = Path.Combine(quarantineDir, quarantineName);

                // Move file to quarantine
                File.Move(filePath, quarantinePath);

                // Create metadata file
                var metadataPath = Path.ChangeExtension(quarantinePath, ".metadata");
                var metadata = new
                {
                    OriginalPath = filePath,
                    QuarantinedAt = DateTime.UtcNow,
                    Reason = reason,
                    FileHash = await CalculateFileHashAsync(quarantinePath)
                };

                await File.WriteAllTextAsync(metadataPath, 
                    System.Text.Json.JsonSerializer.Serialize(metadata, new System.Text.Json.JsonSerializerOptions 
                    { 
                        WriteIndented = true 
                    }));

                _logger.LogWarning("File quarantined: {FilePath} -> {QuarantinePath}, Reason: {Reason}", 
                    filePath, quarantinePath, reason);

                return new QuarantineResult
                {
                    Success = true,
                    QuarantinePath = quarantinePath,
                    Reason = reason
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error quarantining file: {FilePath}", filePath);
                return new QuarantineResult
                {
                    Success = false,
                    Reason = $"Quarantine failed: {ex.Message}"
                };
            }
        }

        public async Task<ProcessingResult> ProcessLargeFileAsync(string filePath)
        {
            var analysisId = Guid.NewGuid();
            var chunkSize = _configuration.GetValue<int>("FileProcessing:ChunkSize", 10485760); // 10MB
            var fileInfo = new FileInfo(filePath);
            var totalChunks = (int)Math.Ceiling((double)fileInfo.Length / chunkSize);

            _logger.LogInformation("Processing large file {FilePath} in {TotalChunks} chunks", filePath, totalChunks);

            try
            {
                await SendProgressUpdate(analysisId, 5, $"Processing large file in {totalChunks} chunks");

                var allIOCs = new List<ExtractedIOC>();
                var processedBytes = 0L;

                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                using var reader = new StreamReader(fs);

                var buffer = new char[chunkSize];
                var chunkIndex = 0;

                while (!reader.EndOfStream)
                {
                    var bytesRead = await reader.ReadAsync(buffer, 0, buffer.Length);
                    var chunkContent = new string(buffer, 0, bytesRead);

                    // Process chunk
                    var chunkIOCs = await _iocExtractor.ExtractIOCsAsync(chunkContent, 
                        new IOCExtractionOptions 
                        { 
                            AnalysisId = analysisId,
                            ChunkIndex = chunkIndex
                        });

                    allIOCs.AddRange(chunkIOCs);
                    processedBytes += bytesRead;

                    // Update progress
                    var progress = (int)((processedBytes * 100) / fileInfo.Length);
                    await SendProgressUpdate(analysisId, progress, 
                        $"Processing chunk {chunkIndex + 1}/{totalChunks}");

                    chunkIndex++;

                    // Add delay to prevent overwhelming the system
                    if (chunkIndex % 10 == 0)
                    {
                        await Task.Delay(100);
                    }
                }

                // Deduplicate IOCs
                var uniqueIOCs = allIOCs
                    .GroupBy(i => new { i.Type, i.Value })
                    .Select(g => g.OrderByDescending(i => i.Confidence).First())
                    .ToList();

                _logger.LogInformation("Large file processing completed. Found {TotalIOCs} IOCs ({UniqueIOCs} unique)", 
                    allIOCs.Count, uniqueIOCs.Count);

                return new ProcessingResult
                {
                    Success = true,
                    Message = "Large file processed successfully",
                    AnalysisId = analysisId,
                    IOCCount = uniqueIOCs.Count
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing large file: {FilePath}", filePath);
                return new ProcessingResult
                {
                    Success = false,
                    Message = $"Large file processing failed: {ex.Message}",
                    AnalysisId = analysisId
                };
            }
        }

        private async Task SendProgressUpdate(Guid analysisId, int percentage, string status)
        {
            await _hubContext.Clients.Group($"analysis-{analysisId}")
                .ReceiveAnalysisProgress(analysisId.ToString(), percentage, status);
        }

        private string CalculateSeverity(ExtractedIOC ioc)
        {
            if (ioc.Confidence > 0.9 && (ioc.Type == IOCType.IPv4 || ioc.Type == IOCType.Domain))
                return "Critical";
            if (ioc.Confidence > 0.7)
                return "High";
            if (ioc.Confidence > 0.5)
                return "Medium";
            return "Low";
        }

        private double CalculateThreatLevel(List<ExtractedIOC> iocs, List<MITRETechnique> techniques)
        {
            var iocScore = iocs.Sum(i => i.Confidence) / Math.Max(iocs.Count, 1);
            var techniqueScore = techniques.Sum(t => t.Confidence) / Math.Max(techniques.Count, 1);
            var highConfidenceIOCs = iocs.Count(i => i.Confidence > 0.8);
            var criticalTechniques = techniques.Count(t => t.Severity == "Critical");

            var threatLevel = (iocScore * 0.3) + (techniqueScore * 0.3) + 
                             (highConfidenceIOCs * 0.02) + (criticalTechniques * 0.05);

            return Math.Min(Math.Max(threatLevel, 0.0), 1.0);
        }

        private async Task<string> CalculateFileHashAsync(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
            var hash = await sha256.ComputeHashAsync(fs);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private async Task<MalwareScanResult> ScanForMalwareAsync(string filePath)
        {
            // Basic signature-based scanning
            var signatures = _configuration.GetSection("FileProcessing:MalwareSignatures")
                .Get<string[]>() ?? Array.Empty<string>();

            if (signatures.Length == 0)
            {
                return new MalwareScanResult { IsClean = true };
            }

            try
            {
                var content = await File.ReadAllTextAsync(filePath);
                foreach (var signature in signatures)
                {
                    if (content.Contains(signature, StringComparison.OrdinalIgnoreCase))
                    {
                        return new MalwareScanResult
                        {
                            IsClean = false,
                            Reason = $"Malware signature detected: {signature}"
                        };
                    }
                }

                return new MalwareScanResult { IsClean = true };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Unable to scan file for malware: {FilePath}", filePath);
                return new MalwareScanResult { IsClean = true }; // Allow file if scan fails
            }
        }
    }

    public class ProcessingResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public Guid AnalysisId { get; set; }
        public int IOCCount { get; set; }
        public int MITRECount { get; set; }
        public double ThreatLevel { get; set; }
    }

    public class FileValidationResult
    {
        public bool IsValid { get; set; }
        public string Message { get; set; }
    }

    public class QuarantineResult
    {
        public bool Success { get; set; }
        public string QuarantinePath { get; set; }
        public string Reason { get; set; }
    }

    public class MalwareScanResult
    {
        public bool IsClean { get; set; }
        public string Reason { get; set; }
    }
}