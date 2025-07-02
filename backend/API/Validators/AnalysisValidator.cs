using FluentValidation;
using SecuNikLogX.API.DTOs;
using Microsoft.Extensions.Options;
using SecuNikLogX.API.Configuration;
using System.Text.RegularExpressions;

namespace SecuNikLogX.API.Validators
{
    /// <summary>
    /// FluentValidation implementation for analysis-related requests
    /// </summary>

    /// <summary>
    /// Validator for analysis creation requests
    /// </summary>
    public class AnalysisCreateRequestValidator : AbstractValidator<AnalysisCreateRequest>
    {
        private readonly ForensicsOptions _forensicsOptions;
        private readonly SecurityOptions _securityOptions;

        public AnalysisCreateRequestValidator(
            IOptions<ForensicsOptions> forensicsOptions,
            IOptions<SecurityOptions> securityOptions)
        {
            _forensicsOptions = forensicsOptions?.Value ?? throw new ArgumentNullException(nameof(forensicsOptions));
            _securityOptions = securityOptions?.Value ?? throw new ArgumentNullException(nameof(securityOptions));

            SetupValidationRules();
        }

        private void SetupValidationRules()
        {
            // File path validation with security checks
            RuleFor(x => x.FilePath)
                .NotEmpty()
                .WithMessage("File path is required for forensics analysis")
                .MaximumLength(500)
                .WithMessage("File path cannot exceed 500 characters")
                .Must(BeValidFilePath)
                .WithMessage("File path contains invalid characters or patterns")
                .Must(NotContainDirectoryTraversal)
                .WithMessage("File path cannot contain directory traversal patterns for security")
                .Must(BeWithinAllowedDirectories)
                .WithMessage("File path must be within allowed forensics directories");

            // File name validation
            RuleFor(x => x.FileName)
                .NotEmpty()
                .WithMessage("File name is required")
                .MaximumLength(255)
                .WithMessage("File name cannot exceed 255 characters")
                .Must(BeValidFileName)
                .WithMessage("File name contains invalid characters")
                .Must(HaveValidFileExtension)
                .WithMessage("File extension is not supported for forensics analysis");

            // File size validation with configurable limits
            RuleFor(x => x.FileSize)
                .GreaterThan(0)
                .WithMessage("File size must be greater than 0 bytes")
                .LessThanOrEqualTo(_forensicsOptions.MaxFileSizeBytes)
                .WithMessage($"File size cannot exceed {_forensicsOptions.MaxFileSizeBytes / (1024 * 1024)} MB for forensics analysis");

            // File hash validation for SHA256
            RuleFor(x => x.FileHash)
                .NotEmpty()
                .WithMessage("File hash is required for integrity verification")
                .Length(64)
                .WithMessage("File hash must be exactly 64 characters for SHA256")
                .Matches(@"^[a-fA-F0-9]{64}$")
                .WithMessage("File hash must be a valid hexadecimal SHA256 hash");

            // Analysis type validation
            RuleFor(x => x.AnalysisType)
                .NotEmpty()
                .WithMessage("Analysis type is required")
                .MaximumLength(50)
                .WithMessage("Analysis type cannot exceed 50 characters")
                .Must(BeValidAnalysisType)
                .WithMessage("Analysis type is not supported");

            // Priority validation
            RuleFor(x => x.Priority)
                .InclusiveBetween(1, 5)
                .WithMessage("Priority must be between 1 (lowest) and 5 (highest)");

            // Notes validation
            RuleFor(x => x.Notes)
                .MaximumLength(1000)
                .WithMessage("Notes cannot exceed 1000 characters")
                .Must(NotContainMaliciousContent)
                .WithMessage("Notes contain potentially malicious content")
                .When(x => !string.IsNullOrEmpty(x.Notes));

            // Configuration validation
            RuleFor(x => x.Configuration)
                .Must(BeValidConfiguration)
                .WithMessage("Configuration contains invalid parameters")
                .Must(NotExceedMaxConfigurationSize)
                .WithMessage("Configuration is too large")
                .When(x => x.Configuration != null);
        }

        private bool BeValidFilePath(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return false;

            // Check for invalid path characters
            var invalidChars = Path.GetInvalidPathChars();
            return !filePath.Any(c => invalidChars.Contains(c));
        }

        private bool NotContainDirectoryTraversal(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return false;

            // Check for directory traversal patterns
            var dangerouspPatterns = new[] { "..", "~/", "\\", "%2e%2e", "%2f", "%5c" };
            return !dangerouspPatterns.Any(pattern => filePath.Contains(pattern, StringComparison.OrdinalIgnoreCase));
        }

        private bool BeWithinAllowedDirectories(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return false;

            try
            {
                var fullPath = Path.GetFullPath(filePath);
                var allowedPaths = _forensicsOptions.AllowedUploadPaths ?? new[] { "./uploads/", "./evidence/", "./data/" };

                return allowedPaths.Any(allowedPath =>
                {
                    var fullAllowedPath = Path.GetFullPath(allowedPath);
                    return fullPath.StartsWith(fullAllowedPath, StringComparison.OrdinalIgnoreCase);
                });
            }
            catch
            {
                return false;
            }
        }

        private bool BeValidFileName(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                return false;

            // Check for invalid filename characters
            var invalidChars = Path.GetInvalidFileNameChars();
            return !fileName.Any(c => invalidChars.Contains(c));
        }

        private bool HaveValidFileExtension(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                return false;

            var extension = Path.GetExtension(fileName).ToLowerInvariant();
            var allowedExtensions = _forensicsOptions.AllowedFileExtensions ?? new[]
            {
                ".exe", ".dll", ".bin", ".img", ".vmdk", ".vdi", ".vhd",
                ".log", ".txt", ".csv", ".json", ".xml", ".pcap", ".cap",
                ".evtx", ".reg", ".mem", ".raw", ".dd", ".e01", ".l01"
            };

            return allowedExtensions.Contains(extension);
        }

        private bool BeValidAnalysisType(string analysisType)
        {
            if (string.IsNullOrWhiteSpace(analysisType))
                return false;

            var validTypes = _forensicsOptions.SupportedAnalysisTypes ?? new[]
            {
                "Static", "Dynamic", "Behavioral", "Memory", "Network",
                "Registry", "FileSystem", "Malware", "Artifact", "Timeline"
            };

            return validTypes.Contains(analysisType, StringComparer.OrdinalIgnoreCase);
        }

        private bool NotContainMaliciousContent(string? content)
        {
            if (string.IsNullOrEmpty(content))
                return true;

            // Check for potentially malicious patterns
            var maliciousPatterns = new[]
            {
                @"<script[^>]*>.*?</script>",
                @"javascript:",
                @"vbscript:",
                @"onload\s*=",
                @"onerror\s*=",
                @"eval\s*\(",
                @"expression\s*\("
            };

            return !maliciousPatterns.Any(pattern =>
                Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline));
        }

        private bool BeValidConfiguration(Dictionary<string, object>? configuration)
        {
            if (configuration == null)
                return true;

            // Check configuration keys and values
            var allowedKeys = _forensicsOptions.AllowedConfigurationKeys ?? new[]
            {
                "timeout", "depth", "threads", "memory_limit", "scan_archives",
                "include_metadata", "preserve_timestamps", "analysis_level"
            };

            return configuration.Keys.All(key => allowedKeys.Contains(key, StringComparer.OrdinalIgnoreCase));
        }

        private bool NotExceedMaxConfigurationSize(Dictionary<string, object>? configuration)
        {
            if (configuration == null)
                return true;

            // Approximate size check for configuration
            var maxSize = _securityOptions.MaxRequestSizeKB * 1024 / 10; // 10% of max request size
            var approximateSize = configuration.Sum(kvp =>
                kvp.Key.Length + (kvp.Value?.ToString()?.Length ?? 0));

            return approximateSize <= maxSize;
        }
    }

    /// <summary>
    /// Validator for analysis update requests
    /// </summary>
    public class AnalysisUpdateRequestValidator : AbstractValidator<AnalysisUpdateRequest>
    {
        private readonly ForensicsOptions _forensicsOptions;

        public AnalysisUpdateRequestValidator(IOptions<ForensicsOptions> forensicsOptions)
        {
            _forensicsOptions = forensicsOptions?.Value ?? throw new ArgumentNullException(nameof(forensicsOptions));

            SetupValidationRules();
        }

        private void SetupValidationRules()
        {
            // Priority validation
            RuleFor(x => x.Priority)
                .InclusiveBetween(1, 5)
                .WithMessage("Priority must be between 1 (lowest) and 5 (highest)")
                .When(x => x.Priority.HasValue);

            // Notes validation
            RuleFor(x => x.Notes)
                .MaximumLength(1000)
                .WithMessage("Notes cannot exceed 1000 characters")
                .Must(NotContainMaliciousContent)
                .WithMessage("Notes contain potentially malicious content")
                .When(x => !string.IsNullOrEmpty(x.Notes));

            // Threat level validation
            RuleFor(x => x.ThreatLevel)
                .MaximumLength(50)
                .WithMessage("Threat level cannot exceed 50 characters")
                .Must(BeValidThreatLevel)
                .WithMessage("Threat level is not valid")
                .When(x => !string.IsNullOrEmpty(x.ThreatLevel));

            // Metadata validation
            RuleFor(x => x.Metadata)
                .Must(BeValidMetadata)
                .WithMessage("Metadata contains invalid data")
                .Must(NotExceedMaxMetadataSize)
                .WithMessage("Metadata is too large")
                .When(x => x.Metadata != null);
        }

        private bool NotContainMaliciousContent(string? content)
        {
            if (string.IsNullOrEmpty(content))
                return true;

            var maliciousPatterns = new[]
            {
                @"<script[^>]*>.*?</script>",
                @"javascript:",
                @"vbscript:",
                @"onload\s*=",
                @"onerror\s*=",
                @"eval\s*\(",
                @"expression\s*\("
            };

            return !maliciousPatterns.Any(pattern =>
                Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline));
        }

        private bool BeValidThreatLevel(string? threatLevel)
        {
            if (string.IsNullOrEmpty(threatLevel))
                return true;

            var validLevels = new[] { "None", "Low", "Medium", "High", "Critical", "Unknown" };
            return validLevels.Contains(threatLevel, StringComparer.OrdinalIgnoreCase);
        }

        private bool BeValidMetadata(Dictionary<string, object>? metadata)
        {
            if (metadata == null)
                return true;

            // Validate metadata keys and values
            return metadata.All(kvp =>
                !string.IsNullOrWhiteSpace(kvp.Key) &&
                kvp.Key.Length <= 100 &&
                (kvp.Value == null || kvp.Value.ToString()?.Length <= 500));
        }

        private bool NotExceedMaxMetadataSize(Dictionary<string, object>? metadata)
        {
            if (metadata == null)
                return true;

            var maxSize = 10240; // 10KB limit for metadata
            var approximateSize = metadata.Sum(kvp =>
                kvp.Key.Length + (kvp.Value?.ToString()?.Length ?? 0));

            return approximateSize <= maxSize;
        }
    }

    /// <summary>
    /// Validator for file upload requests for analysis
    /// </summary>
    public class FileUploadRequestValidator : AbstractValidator<FileUploadRequest>
    {
        private readonly FileStorageOptions _fileStorageOptions;
        private readonly SecurityOptions _securityOptions;
        private readonly ForensicsOptions _forensicsOptions;

        public FileUploadRequestValidator(
            IOptions<FileStorageOptions> fileStorageOptions,
            IOptions<SecurityOptions> securityOptions,
            IOptions<ForensicsOptions> forensicsOptions)
        {
            _fileStorageOptions = fileStorageOptions?.Value ?? throw new ArgumentNullException(nameof(fileStorageOptions));
            _securityOptions = securityOptions?.Value ?? throw new ArgumentNullException(nameof(securityOptions));
            _forensicsOptions = forensicsOptions?.Value ?? throw new ArgumentNullException(nameof(forensicsOptions));

            SetupValidationRules();
        }

        private void SetupValidationRules()
        {
            // File validation
            RuleFor(x => x.File)
                .NotNull()
                .WithMessage("File is required for analysis")
                .Must(HaveValidFileSize)
                .WithMessage($"File size must be between 1 byte and {_fileStorageOptions.MaxFileSizeMB} MB")
                .Must(HaveValidFileExtension)
                .WithMessage("File type is not supported for forensics analysis")
                .Must(NotExceedUploadLimits)
                .WithMessage("File upload exceeds system limits");

            // Analysis type validation
            RuleFor(x => x.AnalysisType)
                .NotEmpty()
                .WithMessage("Analysis type is required")
                .MaximumLength(50)
                .WithMessage("Analysis type cannot exceed 50 characters")
                .Must(BeValidAnalysisType)
                .WithMessage("Analysis type is not supported");

            // Priority validation
            RuleFor(x => x.Priority)
                .InclusiveBetween(1, 5)
                .WithMessage("Priority must be between 1 (lowest) and 5 (highest)");

            // Description validation
            RuleFor(x => x.Description)
                .MaximumLength(500)
                .WithMessage("Description cannot exceed 500 characters")
                .Must(NotContainMaliciousContent)
                .WithMessage("Description contains potentially malicious content")
                .When(x => !string.IsNullOrEmpty(x.Description));

            // Configuration validation
            RuleFor(x => x.Configuration)
                .Must(BeValidConfiguration)
                .WithMessage("Configuration contains invalid parameters")
                .Must(NotExceedMaxConfigurationSize)
                .WithMessage("Configuration is too large")
                .When(x => x.Configuration != null);

            // Tags validation
            RuleFor(x => x.Tags)
                .Must(BeValidTags)
                .WithMessage("Tags contain invalid values")
                .Must(NotExceedMaxTagCount)
                .WithMessage($"Cannot exceed {_forensicsOptions.MaxTagsPerFile} tags per file")
                .When(x => x.Tags != null);
        }

        private bool HaveValidFileSize(IFormFile file)
        {
            if (file == null)
                return false;

            var maxSizeBytes = _fileStorageOptions.MaxFileSizeMB * 1024 * 1024;
            return file.Length > 0 && file.Length <= maxSizeBytes;
        }

        private bool HaveValidFileExtension(IFormFile file)
        {
            if (file == null || string.IsNullOrEmpty(file.FileName))
                return false;

            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
            var allowedExtensions = _fileStorageOptions.AllowedExtensions ?? new[]
            {
                ".exe", ".dll", ".bin", ".img", ".vmdk", ".vdi", ".vhd",
                ".log", ".txt", ".csv", ".json", ".xml", ".pcap", ".cap",
                ".evtx", ".reg", ".mem", ".raw", ".dd", ".e01", ".l01"
            };

            return allowedExtensions.Contains(extension);
        }

        private bool NotExceedUploadLimits(IFormFile file)
        {
            if (file == null)
                return false;

            // Additional checks for upload limits
            var maxConcurrentUploads = _securityOptions.MaxConcurrentUploads;
            var maxDailyUploads = _securityOptions.MaxDailyUploadsPerUser;

            // These would typically be checked against database/cache
            // For now, just validate basic file constraints
            return file.Length <= int.MaxValue; // Ensure file size fits in memory
        }

        private bool BeValidAnalysisType(string analysisType)
        {
            if (string.IsNullOrWhiteSpace(analysisType))
                return false;

            var validTypes = _forensicsOptions.SupportedAnalysisTypes ?? new[]
            {
                "Static", "Dynamic", "Behavioral", "Memory", "Network",
                "Registry", "FileSystem", "Malware", "Artifact", "Timeline"
            };

            return validTypes.Contains(analysisType, StringComparer.OrdinalIgnoreCase);
        }

        private bool NotContainMaliciousContent(string? content)
        {
            if (string.IsNullOrEmpty(content))
                return true;

            var maliciousPatterns = new[]
            {
                @"<script[^>]*>.*?</script>",
                @"javascript:",
                @"vbscript:",
                @"onload\s*=",
                @"onerror\s*=",
                @"eval\s*\(",
                @"expression\s*\("
            };

            return !maliciousPatterns.Any(pattern =>
                Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline));
        }

        private bool BeValidConfiguration(Dictionary<string, object>? configuration)
        {
            if (configuration == null)
                return true;

            var allowedKeys = _forensicsOptions.AllowedConfigurationKeys ?? new[]
            {
                "timeout", "depth", "threads", "memory_limit", "scan_archives",
                "include_metadata", "preserve_timestamps", "analysis_level"
            };

            return configuration.Keys.All(key => allowedKeys.Contains(key, StringComparer.OrdinalIgnoreCase));
        }

        private bool NotExceedMaxConfigurationSize(Dictionary<string, object>? configuration)
        {
            if (configuration == null)
                return true;

            var maxSize = 5120; // 5KB limit for configuration
            var approximateSize = configuration.Sum(kvp =>
                kvp.Key.Length + (kvp.Value?.ToString()?.Length ?? 0));

            return approximateSize <= maxSize;
        }

        private bool BeValidTags(List<string>? tags)
        {
            if (tags == null)
                return true;

            return tags.All(tag =>
                !string.IsNullOrWhiteSpace(tag) &&
                tag.Length <= 50 &&
                !tag.Contains(' ') && // No spaces in tags
                Regex.IsMatch(tag, @"^[a-zA-Z0-9_-]+$")); // Only alphanumeric, underscore, dash
        }

        private bool NotExceedMaxTagCount(List<string>? tags)
        {
            if (tags == null)
                return true;

            var maxTags = _forensicsOptions.MaxTagsPerFile;
            return tags.Count <= maxTags;
        }
    }

    /// <summary>
    /// Validator for analysis query parameters
    /// </summary>
    public class AnalysisQueryValidator : AbstractValidator<AnalysisQueryParameters>
    {
        public AnalysisQueryValidator()
        {
            SetupValidationRules();
        }

        private void SetupValidationRules()
        {
            // Page number validation
            RuleFor(x => x.PageNumber)
                .GreaterThan(0)
                .WithMessage("Page number must be greater than 0")
                .LessThanOrEqualTo(10000)
                .WithMessage("Page number cannot exceed 10000");

            // Page size validation
            RuleFor(x => x.PageSize)
                .InclusiveBetween(1, 100)
                .WithMessage("Page size must be between 1 and 100");

            // Date range validation
            RuleFor(x => x.StartDate)
                .LessThan(x => x.EndDate)
                .WithMessage("Start date must be before end date")
                .When(x => x.StartDate.HasValue && x.EndDate.HasValue);

            RuleFor(x => x.EndDate)
                .GreaterThan(DateTime.MinValue)
                .WithMessage("End date must be a valid date")
                .LessThanOrEqualTo(DateTime.UtcNow.AddDays(1))
                .WithMessage("End date cannot be in the future")
                .When(x => x.EndDate.HasValue);

            // Status validation
            RuleFor(x => x.Status)
                .Must(BeValidStatus)
                .WithMessage("Invalid analysis status")
                .When(x => !string.IsNullOrEmpty(x.Status));

            // Threat level validation
            RuleFor(x => x.ThreatLevel)
                .Must(BeValidThreatLevel)
                .WithMessage("Invalid threat level")
                .When(x => !string.IsNullOrEmpty(x.ThreatLevel));

            // Search query validation
            RuleFor(x => x.Query)
                .MaximumLength(200)
                .WithMessage("Search query cannot exceed 200 characters")
                .Must(NotContainMaliciousContent)
                .WithMessage("Search query contains invalid characters")
                .When(x => !string.IsNullOrEmpty(x.Query));
        }

        private bool BeValidStatus(string? status)
        {
            if (string.IsNullOrEmpty(status))
                return true;

            var validStatuses = new[] { "Pending", "Running", "Completed", "Failed", "Paused", "Cancelled" };
            return validStatuses.Contains(status, StringComparer.OrdinalIgnoreCase);
        }

        private bool BeValidThreatLevel(string? threatLevel)
        {
            if (string.IsNullOrEmpty(threatLevel))
                return true;

            var validLevels = new[] { "None", "Low", "Medium", "High", "Critical", "Unknown" };
            return validLevels.Contains(threatLevel, StringComparer.OrdinalIgnoreCase);
        }

        private bool NotContainMaliciousContent(string? content)
        {
            if (string.IsNullOrEmpty(content))
                return true;

            // Prevent SQL injection and XSS in search queries
            var dangerousPatterns = new[]
            {
                @"['""`;]",
                @"<script",
                @"javascript:",
                @"vbscript:",
                @"union\s+select",
                @"drop\s+table",
                @"delete\s+from",
                @"insert\s+into",
                @"update\s+set"
            };

            return !dangerousPatterns.Any(pattern =>
                Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));
        }
    }

    /// <summary>
    /// Query parameters for analysis filtering
    /// </summary>
    public class AnalysisQueryParameters
    {
        public int PageNumber { get; set; } = 1;
        public int PageSize { get; set; } = 20;
        public DateTime? StartDate { get; set; }
        public DateTime? EndDate { get; set; }
        public string? Status { get; set; }
        public string? ThreatLevel { get; set; }
        public string? Query { get; set; }
        public string? FileType { get; set; }
        public string? SortBy { get; set; }
        public string? SortOrder { get; set; }
    }
}