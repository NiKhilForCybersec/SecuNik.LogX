using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Configuration;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace SecuNik.LogX.Api.Services.Storage
{
    public class LocalStorageService : IStorageService
    {
        private readonly StorageOptions _options;
        private readonly ILogger<LocalStorageService> _logger;

        public LocalStorageService(IOptions<StorageOptions> options, ILogger<LocalStorageService> logger)
        {
            _options = options.Value;
            _logger = logger;
            
            // Ensure storage directories exist
            EnsureDirectoriesExist();
        }

        public async Task<string> SaveFileAsync(Guid analysisId, string fileName, Stream fileStream, CancellationToken cancellationToken = default)
        {
            try
            {
                var analysisDirectory = GetAnalysisDirectory(analysisId);
                Directory.CreateDirectory(analysisDirectory);

                var filePath = Path.Combine(analysisDirectory, fileName);
                
                using (var fileOutput = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 
                    bufferSize: 4096, useAsync: true))
                {
                    await fileStream.CopyToAsync(fileOutput, cancellationToken);
                }
                
                _logger.LogInformation("Saved file {FileName} for analysis {AnalysisId}", fileName, analysisId);
                return filePath;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving file {FileName} for analysis {AnalysisId}", fileName, analysisId);
                throw;
            }
        }

        public async Task<Stream> GetFileAsync(Guid analysisId, string fileName, CancellationToken cancellationToken = default)
        {
            try
            {
                var filePath = Path.Combine(GetAnalysisDirectory(analysisId), fileName);
                
                if (!File.Exists(filePath))
                {
                    throw new FileNotFoundException($"File {fileName} not found for analysis {analysisId}", filePath);
                }
                
                return new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 
                    bufferSize: 4096, useAsync: true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting file {FileName} for analysis {AnalysisId}", fileName, analysisId);
                throw;
            }
        }

        public async Task<bool> DeleteFileAsync(Guid analysisId, string fileName, CancellationToken cancellationToken = default)
        {
            try
            {
                var filePath = Path.Combine(GetAnalysisDirectory(analysisId), fileName);
                
                if (!File.Exists(filePath))
                {
                    _logger.LogWarning("File {FileName} not found for analysis {AnalysisId}", fileName, analysisId);
                    return false;
                }
                
                File.Delete(filePath);
                _logger.LogInformation("Deleted file {FileName} for analysis {AnalysisId}", fileName, analysisId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting file {FileName} for analysis {AnalysisId}", fileName, analysisId);
                return false;
            }
        }

        public async Task<bool> FileExistsAsync(Guid analysisId, string fileName, CancellationToken cancellationToken = default)
        {
            try
            {
                var filePath = Path.Combine(GetAnalysisDirectory(analysisId), fileName);
                return File.Exists(filePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking if file {FileName} exists for analysis {AnalysisId}", fileName, analysisId);
                return false;
            }
        }

        public async Task SaveAnalysisResultAsync(Guid analysisId, string resultType, object data, CancellationToken cancellationToken = default)
        {
            try
            {
                var resultsDirectory = GetResultsDirectory(analysisId);
                Directory.CreateDirectory(resultsDirectory);
                
                var filePath = Path.Combine(resultsDirectory, $"{resultType}.json");
                var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
                
                using (var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 
                    bufferSize: 4096, useAsync: true))
                {
                    await JsonSerializer.SerializeAsync(fileStream, data, jsonOptions, cancellationToken);
                }
                
                _logger.LogInformation("Saved analysis result {ResultType} for analysis {AnalysisId}", resultType, analysisId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving analysis result {ResultType} for analysis {AnalysisId}", resultType, analysisId);
                throw;
            }
        }

        public async Task<T?> GetAnalysisResultAsync<T>(Guid analysisId, string resultType, CancellationToken cancellationToken = default) where T : class
        {
            try
            {
                var filePath = Path.Combine(GetResultsDirectory(analysisId), $"{resultType}.json");
                
                if (!File.Exists(filePath))
                {
                    _logger.LogWarning("Analysis result {ResultType} not found for analysis {AnalysisId}", resultType, analysisId);
                    return null;
                }
                
                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 
                    bufferSize: 4096, useAsync: true))
                {
                    return await JsonSerializer.DeserializeAsync<T>(fileStream, cancellationToken: cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting analysis result {ResultType} for analysis {AnalysisId}", resultType, analysisId);
                return null;
            }
        }

        public async Task<bool> DeleteAnalysisResultAsync(Guid analysisId, string resultType, CancellationToken cancellationToken = default)
        {
            try
            {
                var filePath = Path.Combine(GetResultsDirectory(analysisId), $"{resultType}.json");
                
                if (!File.Exists(filePath))
                {
                    _logger.LogWarning("Analysis result {ResultType} not found for analysis {AnalysisId}", resultType, analysisId);
                    return false;
                }
                
                File.Delete(filePath);
                _logger.LogInformation("Deleted analysis result {ResultType} for analysis {AnalysisId}", resultType, analysisId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting analysis result {ResultType} for analysis {AnalysisId}", resultType, analysisId);
                return false;
            }
        }

        public async Task<string> SaveParserAsync(string parserName, string content, CancellationToken cancellationToken = default)
        {
            try
            {
                var parsersDirectory = Path.Combine(_options.BasePath, _options.ParsersPath, "UserDefined");
                Directory.CreateDirectory(parsersDirectory);
                
                var filePath = Path.Combine(parsersDirectory, $"{SanitizeFileName(parserName)}.cs");
                await File.WriteAllTextAsync(filePath, content, cancellationToken);
                
                _logger.LogInformation("Saved parser {ParserName} to {FilePath}", parserName, filePath);
                return filePath;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving parser {ParserName}", parserName);
                throw;
            }
        }

        public async Task<string?> GetParserAsync(string parserName, CancellationToken cancellationToken = default)
        {
            try
            {
                var parsersDirectory = Path.Combine(_options.BasePath, _options.ParsersPath, "UserDefined");
                var filePath = Path.Combine(parsersDirectory, $"{SanitizeFileName(parserName)}.cs");
                
                if (!File.Exists(filePath))
                {
                    _logger.LogWarning("Parser {ParserName} not found", parserName);
                    return null;
                }
                
                return await File.ReadAllTextAsync(filePath, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting parser {ParserName}", parserName);
                return null;
            }
        }

        public async Task<bool> DeleteParserAsync(string parserName, CancellationToken cancellationToken = default)
        {
            try
            {
                var parsersDirectory = Path.Combine(_options.BasePath, _options.ParsersPath, "UserDefined");
                var filePath = Path.Combine(parsersDirectory, $"{SanitizeFileName(parserName)}.cs");
                
                if (!File.Exists(filePath))
                {
                    _logger.LogWarning("Parser {ParserName} not found", parserName);
                    return false;
                }
                
                File.Delete(filePath);
                _logger.LogInformation("Deleted parser {ParserName}", parserName);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting parser {ParserName}", parserName);
                return false;
            }
        }

        public async Task<List<string>> ListParsersAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var parsersDirectory = Path.Combine(_options.BasePath, _options.ParsersPath, "UserDefined");
                
                if (!Directory.Exists(parsersDirectory))
                {
                    return new List<string>();
                }
                
                var files = Directory.GetFiles(parsersDirectory, "*.cs");
                return files.Select(f => Path.GetFileNameWithoutExtension(f)).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error listing parsers");
                return new List<string>();
            }
        }

        public async Task<string> SaveRuleAsync(string ruleName, string ruleType, string content, CancellationToken cancellationToken = default)
        {
            try
            {
                var rulesDirectory = Path.Combine(_options.BasePath, _options.RulesPath, ruleType);
                Directory.CreateDirectory(rulesDirectory);
                
                var extension = GetRuleFileExtension(ruleType);
                var filePath = Path.Combine(rulesDirectory, $"{SanitizeFileName(ruleName)}{extension}");
                await File.WriteAllTextAsync(filePath, content, cancellationToken);
                
                _logger.LogInformation("Saved rule {RuleName} to {FilePath}", ruleName, filePath);
                return filePath;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving rule {RuleName}", ruleName);
                throw;
            }
        }

        public async Task<string?> GetRuleAsync(string ruleName, string ruleType, CancellationToken cancellationToken = default)
        {
            try
            {
                var rulesDirectory = Path.Combine(_options.BasePath, _options.RulesPath, ruleType);
                var extension = GetRuleFileExtension(ruleType);
                var filePath = Path.Combine(rulesDirectory, $"{SanitizeFileName(ruleName)}{extension}");
                
                if (!File.Exists(filePath))
                {
                    _logger.LogWarning("Rule {RuleName} not found", ruleName);
                    return null;
                }
                
                return await File.ReadAllTextAsync(filePath, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting rule {RuleName}", ruleName);
                return null;
            }
        }

        public async Task<bool> DeleteRuleAsync(string ruleName, string ruleType, CancellationToken cancellationToken = default)
        {
            try
            {
                var rulesDirectory = Path.Combine(_options.BasePath, _options.RulesPath, ruleType);
                var extension = GetRuleFileExtension(ruleType);
                var filePath = Path.Combine(rulesDirectory, $"{SanitizeFileName(ruleName)}{extension}");
                
                if (!File.Exists(filePath))
                {
                    _logger.LogWarning("Rule {RuleName} not found", ruleName);
                    return false;
                }
                
                File.Delete(filePath);
                _logger.LogInformation("Deleted rule {RuleName}", ruleName);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting rule {RuleName}", ruleName);
                return false;
            }
        }

        public async Task<List<string>> ListRulesAsync(string ruleType, CancellationToken cancellationToken = default)
        {
            try
            {
                var rulesDirectory = Path.Combine(_options.BasePath, _options.RulesPath, ruleType);
                
                if (!Directory.Exists(rulesDirectory))
                {
                    return new List<string>();
                }
                
                var extension = GetRuleFileExtension(ruleType);
                var files = Directory.GetFiles(rulesDirectory, $"*{extension}");
                return files.Select(f => Path.GetFileNameWithoutExtension(f)).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error listing rules for type {RuleType}", ruleType);
                return new List<string>();
            }
        }

        public async Task CleanupOldFilesAsync(TimeSpan maxAge, CancellationToken cancellationToken = default)
        {
            try
            {
                var cutoffDate = DateTime.UtcNow - maxAge;
                _logger.LogInformation("Cleaning up files older than {CutoffDate}", cutoffDate);
                
                // Clean up uploads
                await CleanupDirectoryAsync(_options.GetUploadsPath(), cutoffDate, cancellationToken);
                
                // Clean up results
                await CleanupDirectoryAsync(_options.GetResultsPath(), cutoffDate, cancellationToken);
                
                // Clean up temp files
                await CleanupDirectoryAsync(_options.GetTempPath(), cutoffDate, cancellationToken);
                
                _logger.LogInformation("File cleanup completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cleaning up old files");
                throw;
            }
        }

        public async Task<StorageInfo> GetStorageInfoAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var storageDirectory = new DirectoryInfo(_options.BasePath);
                
                if (!storageDirectory.Exists)
                {
                    return new StorageInfo
                    {
                        TotalSpace = 0,
                        UsedSpace = 0,
                        AvailableSpace = 0,
                        TotalFiles = 0,
                        TotalAnalyses = 0,
                        LastCleanup = DateTime.MinValue
                    };
                }
                
                // Get drive info
                var driveInfo = new DriveInfo(storageDirectory.Root.FullName);
                
                // Count files and analyses
                var totalFiles = CountFiles(storageDirectory);
                var totalAnalyses = Directory.Exists(_options.GetUploadsPath()) 
                    ? Directory.GetDirectories(_options.GetUploadsPath()).Length 
                    : 0;
                
                // Calculate used space
                var usedSpace = CalculateDirectorySize(storageDirectory);
                
                return new StorageInfo
                {
                    TotalSpace = driveInfo.TotalSize,
                    UsedSpace = usedSpace,
                    AvailableSpace = driveInfo.AvailableFreeSpace,
                    TotalFiles = totalFiles,
                    TotalAnalyses = totalAnalyses,
                    LastCleanup = GetLastCleanupTime()
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting storage info");
                throw;
            }
        }

        public async Task<bool> CreateAnalysisDirectoryAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            try
            {
                var analysisDirectory = GetAnalysisDirectory(analysisId);
                Directory.CreateDirectory(analysisDirectory);
                
                var resultsDirectory = GetResultsDirectory(analysisId);
                Directory.CreateDirectory(resultsDirectory);
                
                _logger.LogInformation("Created directories for analysis {AnalysisId}", analysisId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating directories for analysis {AnalysisId}", analysisId);
                return false;
            }
        }

        public async Task<bool> DeleteAnalysisDirectoryAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            try
            {
                var analysisDirectory = GetAnalysisDirectory(analysisId);
                if (Directory.Exists(analysisDirectory))
                {
                    Directory.Delete(analysisDirectory, true);
                }
                
                var resultsDirectory = GetResultsDirectory(analysisId);
                if (Directory.Exists(resultsDirectory))
                {
                    Directory.Delete(resultsDirectory, true);
                }
                
                _logger.LogInformation("Deleted directories for analysis {AnalysisId}", analysisId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting directories for analysis {AnalysisId}", analysisId);
                return false;
            }
        }

        public async Task<List<string>> ListAnalysisFilesAsync(Guid analysisId, CancellationToken cancellationToken = default)
        {
            try
            {
                var analysisDirectory = GetAnalysisDirectory(analysisId);
                
                if (!Directory.Exists(analysisDirectory))
                {
                    return new List<string>();
                }
                
                return Directory.GetFiles(analysisDirectory)
                    .Select(Path.GetFileName)
                    .ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error listing files for analysis {AnalysisId}", analysisId);
                return new List<string>();
            }
        }

        private void EnsureDirectoriesExist()
        {
            try
            {
                var directories = new[]
                {
                    _options.BasePath,
                    _options.GetUploadsPath(),
                    _options.GetParsersPath(),
                    Path.Combine(_options.GetParsersPath(), "BuiltIn"),
                    Path.Combine(_options.GetParsersPath(), "UserDefined"),
                    _options.GetRulesPath(),
                    Path.Combine(_options.GetRulesPath(), "YARA"),
                    Path.Combine(_options.GetRulesPath(), "Sigma"),
                    Path.Combine(_options.GetRulesPath(), "STIX"),
                    Path.Combine(_options.GetRulesPath(), "Custom"),
                    _options.GetResultsPath(),
                    _options.GetTempPath()
                };
                
                foreach (var directory in directories)
                {
                    if (!Directory.Exists(directory))
                    {
                        Directory.CreateDirectory(directory);
                        _logger.LogInformation("Created directory: {Directory}", directory);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error ensuring directories exist");
                throw;
            }
        }

        private string GetAnalysisDirectory(Guid analysisId)
        {
            return Path.Combine(_options.GetUploadsPath(), analysisId.ToString());
        }

        private string GetResultsDirectory(Guid analysisId)
        {
            return Path.Combine(_options.GetResultsPath(), analysisId.ToString());
        }

        private string SanitizeFileName(string fileName)
        {
            var invalidChars = Path.GetInvalidFileNameChars();
            var sanitized = new string(fileName.Where(c => !invalidChars.Contains(c)).ToArray());
            return string.IsNullOrWhiteSpace(sanitized) ? "file" : sanitized;
        }

        private string GetRuleFileExtension(string ruleType)
        {
            return ruleType.ToLowerInvariant() switch
            {
                "yara" => ".yar",
                "sigma" => ".yml",
                "stix" => ".json",
                _ => ".txt"
            };
        }

        private async Task CleanupDirectoryAsync(string directory, DateTime cutoffDate, CancellationToken cancellationToken)
        {
            if (!Directory.Exists(directory))
            {
                return;
            }
            
            var dirInfo = new DirectoryInfo(directory);
            var subdirs = dirInfo.GetDirectories();
            
            foreach (var subdir in subdirs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                if (subdir.LastWriteTimeUtc < cutoffDate)
                {
                    try
                    {
                        subdir.Delete(true);
                        _logger.LogInformation("Deleted old directory: {Directory}", subdir.FullName);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error deleting directory {Directory}", subdir.FullName);
                    }
                }
            }
            
            // Also clean up any files directly in the directory
            var files = dirInfo.GetFiles();
            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                if (file.LastWriteTimeUtc < cutoffDate)
                {
                    try
                    {
                        file.Delete();
                        _logger.LogInformation("Deleted old file: {File}", file.FullName);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error deleting file {File}", file.FullName);
                    }
                }
            }
        }

        private int CountFiles(DirectoryInfo directory)
        {
            var count = directory.GetFiles().Length;
            
            foreach (var subdir in directory.GetDirectories())
            {
                count += CountFiles(subdir);
            }
            
            return count;
        }

        private long CalculateDirectorySize(DirectoryInfo directory)
        {
            var size = directory.GetFiles().Sum(file => file.Length);
            
            foreach (var subdir in directory.GetDirectories())
            {
                size += CalculateDirectorySize(subdir);
            }
            
            return size;
        }

        private DateTime GetLastCleanupTime()
        {
            try
            {
                var markerFile = Path.Combine(_options.BasePath, "last_cleanup.txt");
                
                if (File.Exists(markerFile))
                {
                    var content = File.ReadAllText(markerFile);
                    if (DateTime.TryParse(content, out var lastCleanup))
                    {
                        return lastCleanup;
                    }
                }
                
                return DateTime.MinValue;
            }
            catch
            {
                return DateTime.MinValue;
            }
        }

        public string GetAnalysisPath(Guid analysisId)
        {
            return GetAnalysisDirectory(analysisId);
        }
    }
}