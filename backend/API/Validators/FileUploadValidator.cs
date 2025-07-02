using FluentValidation;
using SecuNikLogX.API.DTOs;
using Microsoft.Extensions.Options;
using SecuNikLogX.API.Configuration;
using System.Text.RegularExpressions;

namespace SecuNikLogX.API.Validators
{
    /// <summary>
    /// FluentValidation implementation for file upload and management operations
    /// </summary>

    /// <summary>
    /// Validator for multi-file upload validation with security checks
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
            // File validation with comprehensive security checks
            RuleFor(x => x.File)
                .NotNull()
                .WithMessage("File is required for upload")
                .Must(HaveValidFileSize)
                .WithMessage($"File size must be between 1 byte and {_fileStorageOptions.MaxFileSizeMB} MB")
                .Must(HaveValidFileName)
                .WithMessage("File name contains invalid characters or patterns")
                .Must(HaveValidFileExtension)
                .WithMessage("File extension is not allowed for forensics analysis")
                .Must(NotHaveMaliciousFileName)
                .WithMessage("File name contains potentially malicious patterns")
                .Must(HaveValidMimeType)
                .WithMessage("File MIME type does not match file extension")
                .Must(NotExceedSystemLimits)
                .WithMessage("File upload exceeds system resource limits");

            // Description validation
            RuleFor(x => x.Description)
                .MaximumLength(500)
                .WithMessage("Description cannot exceed 500 characters")
                .Must(NotContainMaliciousContent)
                .WithMessage("Description contains potentially harmful content")
                .Must(NotContainPersonalInformation)
                .WithMessage("Description may contain personal information")
                .When(x => !string.IsNullOrEmpty(x.Description));

            // Tags validation with security and format checks
            RuleFor(x => x.Tags)
                .Must(BeValidTags)
                .WithMessage("Tags contain invalid characters or format")
                .Must(NotExceedMaxTagCount)
                .WithMessage($"Cannot exceed {_forensicsOptions.MaxTagsPerFile} tags per file")
                .Must(NotContainDuplicateTags)
                .WithMessage("Tags cannot contain duplicates")
                .Must(NotContainReservedTags)
                .WithMessage("Tags cannot use reserved system keywords")
                .When(x => x.Tags != null && x.Tags.Any());

            // Validation level validation
            RuleFor(x => x.ValidationLevel)
                .MaximumLength(20)
                .WithMessage("Validation level cannot exceed 20 characters")
                .Must(BeValidValidationLevel)
                .WithMessage("Invalid validation level specified");

            // Metadata validation with size and content restrictions
            RuleFor(x => x.Metadata)
                .Must(BeValidMetadata)
                .WithMessage("Metadata contains invalid keys or values")
                .Must(NotExceedMaxMetadataSize)
                .WithMessage("Metadata size exceeds maximum allowed limit")
                .Must(NotContainSensitiveData)
                .WithMessage("Metadata may contain sensitive information")
                .When(x => x.Metadata != null && x.Metadata.Any());
        }

        private bool HaveValidFileSize(IFormFile file)
        {
            if (file == null)
                return false;

            var maxSizeBytes = _fileStorageOptions.MaxFileSizeMB * 1024L * 1024L;
            var minSizeBytes = _fileStorageOptions.MinFileSizeBytes;

            return file.Length >= minSizeBytes && file.Length <= maxSizeBytes;
        }

        private bool HaveValidFileName(IFormFile file)
        {
            if (file == null || string.IsNullOrEmpty(file.FileName))
                return false;

            var fileName = file.FileName;

            // Check length
            if (fileName.Length > 255)
                return false;

            // Check for invalid characters
            var invalidChars = Path.GetInvalidFileNameChars();
            if (fileName.Any(c => invalidChars.Contains(c)))
                return false;

            // Check for reserved names
            var reservedNames = new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };
            var fileNameWithoutExtension = Path.GetFileNameWithoutExtension(fileName).ToUpperInvariant();
            if (reservedNames.Contains(fileNameWithoutExtension))
                return false;

            return true;
        }

        private bool HaveValidFileExtension(IFormFile file)
        {
            if (file == null || string.IsNullOrEmpty(file.FileName))
                return false;

            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
            
            // Must have an extension
            if (string.IsNullOrEmpty(extension))
                return false;

            var allowedExtensions = _fileStorageOptions.AllowedExtensions ?? new[]
            {
                ".exe", ".dll", ".bin", ".img", ".vmdk", ".vdi", ".vhd", ".vhdx",
                ".log", ".txt", ".csv", ".json", ".xml", ".pcap", ".cap", ".pcapng",
                ".evtx", ".evt", ".reg", ".mem", ".raw", ".dd", ".e01", ".l01", ".s01",
                ".zip", ".7z", ".tar", ".gz", ".rar", ".iso", ".dmg", ".pst", ".ost"
            };

            return allowedExtensions.Contains(extension);
        }

        private bool NotHaveMaliciousFileName(IFormFile file)
        {
            if (file == null || string.IsNullOrEmpty(file.FileName))
                return false;

            var fileName = file.FileName.ToLowerInvariant();

            // Check for suspicious patterns
            var suspiciousPatterns = new[]
            {
                @"\.\.+", // Multiple dots
                @"^\.+", // Starting with dots
                @"[<>:""|?*]", // Special characters
                @"[\x00-\x1f]", // Control characters
                @"autorun\.inf",
                @"desktop\.ini",
                @"thumbs\.db",
                @"\.lnk$",
                @"\.scr$",
                @"\.bat$",
                @"\.cmd$",
                @"\.com$",
                @"\.pif$",
                @"\.vbs$",
                @"\.js$",
                @"\.jar$"
            };

            return !suspiciousPatterns.Any(pattern =>
                Regex.IsMatch(fileName, pattern, RegexOptions.IgnoreCase));
        }

        private bool HaveValidMimeType(IFormFile file)
        {
            if (file == null || string.IsNullOrEmpty(file.FileName) || string.IsNullOrEmpty(file.ContentType))
                return true; // Skip validation if MIME type not provided

            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
            var contentType = file.ContentType.ToLowerInvariant();

            // Define expected MIME types for common forensics file extensions
            var mimeTypeMap = new Dictionary<string, string[]>
            {
                [".exe"] = new[] { "application/x-msdownload", "application/octet-stream", "application/x-executable" },
                [".dll"] = new[] { "application/x-msdownload", "application/octet-stream" },
                [".bin"] = new[] { "application/octet-stream" },
                [".log"] = new[] { "text/plain", "application/octet-stream" },
                [".txt"] = new[] { "text/plain" },
                [".csv"] = new[] { "text/csv", "text/plain" },
                [".json"] = new[] { "application/json", "text/plain" },
                [".xml"] = new[] { "application/xml", "text/xml", "text/plain" },
                [".pcap"] = new[] { "application/vnd.tcpdump.pcap", "application/octet-stream" },
                [".zip"] = new[] { "application/zip", "application/x-zip-compressed" },
                [".7z"] = new[] { "application/x-7z-compressed" },
                [".iso"] = new[] { "application/x-iso9660-image", "application/octet-stream" }
            };

            if (mimeTypeMap.TryGetValue(extension, out var expectedTypes))
            {
                return expectedTypes.Any(expectedType => 
                    contentType.Contains(expectedType, StringComparison.OrdinalIgnoreCase));
            }

            // Allow if extension not in map (will be handled by other validators)
            return true;
        }

        private bool NotExceedSystemLimits(IFormFile file)
        {
            if (file == null)
                return false;

            // Check against available system resources
            var maxMemoryUsage = _securityOptions.MaxMemoryUsageMB * 1024L * 1024L;
            var maxConcurrentUploads = _securityOptions.MaxConcurrentUploads;

            // File size should not exceed 50% of max memory usage
            return file.Length <= (maxMemoryUsage / 2);
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
                @"data:text/html",
                @"onload\s*=",
                @"onerror\s*=",
                @"onclick\s*=",
                @"eval\s*\(",
                @"expression\s*\(",
                @"url\s*\(",
                @"@import",
                @"<?php",
                @"<%",
                @"\${",
                @"<!--#"
            };

            return !maliciousPatterns.Any(pattern =>
                Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline));
        }

        private bool NotContainPersonalInformation(string? content)
        {
            if (string.IsNullOrEmpty(content))
                return true;

            // Basic patterns for common PII
            var piiPatterns = new[]
            {
                @"\b\d{3}-\d{2}-\d{4}\b", // SSN pattern
                @"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", // Credit card pattern
                @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", // Email pattern (if too many)
                @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b" // IP address (if too many)
            };

            // Allow some emails/IPs but flag if too many
            var emailCount = Regex.Matches(content, piiPatterns[2]).Count;
            var ipCount = Regex.Matches(content, piiPatterns[3]).Count;

            if (emailCount > 5 || ipCount > 10)
                return false;

            // Check for SSN and credit card patterns
            return !piiPatterns.Take(2).Any(pattern =>
                Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));
        }

        private bool BeValidTags(List<string>? tags)
        {
            if (tags == null)
                return true;

            return tags.All(tag =>
                !string.IsNullOrWhiteSpace(tag) &&
                tag.Length >= 2 &&
                tag.Length <= 50 &&
                Regex.IsMatch(tag, @"^[a-zA-Z0-9_-]+$") && // Only alphanumeric, underscore, dash
                !tag.StartsWith('-') && // Cannot start with dash
                !tag.EndsWith('-')); // Cannot end with dash
        }

        private bool NotExceedMaxTagCount(List<string>? tags)
        {
            if (tags == null)
                return true;

            var maxTags = _forensicsOptions.MaxTagsPerFile;
            return tags.Count <= maxTags;
        }

        private bool NotContainDuplicateTags(List<string>? tags)
        {
            if (tags == null)
                return true;

            return tags.Count == tags.Distinct(StringComparer.OrdinalIgnoreCase).Count();
        }

        private bool NotContainReservedTags(List<string>? tags)
        {
            if (tags == null)
                return true;

            var reservedTags = new[] { "system", "admin", "root", "internal", "temp", "cache", "log", "error", "debug" };
            return !tags.Any(tag => reservedTags.Contains(tag, StringComparer.OrdinalIgnoreCase));
        }

        private bool BeValidValidationLevel(string validationLevel)
        {
            if (string.IsNullOrEmpty(validationLevel))
                return true; // Default will be used

            var validLevels = new[] { "Basic", "Standard", "Enhanced", "Comprehensive", "Forensic" };
            return validLevels.Contains(validationLevel, StringComparer.OrdinalIgnoreCase);
        }

        private bool BeValidMetadata(Dictionary<string, object>? metadata)
        {
            if (metadata == null)
                return true;

            return metadata.All(kvp =>
            {
                // Key validation
                if (string.IsNullOrWhiteSpace(kvp.Key) || 
                    kvp.Key.Length > 100 ||
                    !Regex.IsMatch(kvp.Key, @"^[a-zA-Z0-9_-]+$"))
                    return false;

                // Value validation
                if (kvp.Value == null)
                    return true;

                var valueStr = kvp.Value.ToString();
                return valueStr != null && valueStr.Length <= 1000;
            });
        }

        private bool NotExceedMaxMetadataSize(Dictionary<string, object>? metadata)
        {
            if (metadata == null)
                return true;

            var maxSize = _securityOptions.MaxRequestSizeKB * 1024 / 20; // 5% of max request size
            var approximateSize = metadata.Sum(kvp =>
                kvp.Key.Length + (kvp.Value?.ToString()?.Length ?? 0));

            return approximateSize <= maxSize;
        }

        private bool NotContainSensitiveData(Dictionary<string, object>? metadata)
        {
            if (metadata == null)
                return true;

            var sensitiveKeys = new[] { "password", "secret", "key", "token", "credential", "auth", "login", "ssn", "social" };
            return !metadata.Keys.Any(key => 
                sensitiveKeys.Any(sensitive => 
                    key.Contains(sensitive, StringComparison.OrdinalIgnoreCase)));
        }
    }

    /// <summary>
    /// Validator for file format and content validation rules
    /// </summary>
    public class FileValidationRequestValidator : AbstractValidator<FileValidationRequest>
    {
        private readonly SecurityOptions _securityOptions;

        public FileValidationRequestValidator(IOptions<SecurityOptions> securityOptions)
        {
            _securityOptions = securityOptions?.Value ?? throw new ArgumentNullException(nameof(securityOptions));

            SetupValidationRules();
        }

        private void SetupValidationRules()
        {
            // Validation level check
            RuleFor(x => x.ValidationLevel)
                .MaximumLength(20)
                .WithMessage("Validation level cannot exceed 20 characters")
                .Must(BeValidValidationLevel)
                .WithMessage("Invalid validation level specified")
                .When(x => !string.IsNullOrEmpty(x.ValidationLevel));

            // Validation rules check
            RuleFor(x => x.ValidationRules)
                .Must(BeValidValidationRules)
                .WithMessage("Invalid validation rules specified")
                .Must(NotExceedMaxRuleCount)
                .WithMessage("Too many validation rules specified")
                .When(x => x.ValidationRules != null && x.ValidationRules.Any());

            // Timeout validation
            RuleFor(x => x.TimeoutSeconds)
                .InclusiveBetween(1, 3600)
                .WithMessage("Timeout must be between 1 and 3600 seconds");

            // Custom parameters validation
            RuleFor(x => x.CustomParameters)
                .Must(BeValidCustomParameters)
                .WithMessage("Custom parameters contain invalid data")
                .Must(NotExceedMaxParameterSize)
                .WithMessage("Custom parameters exceed maximum size")
                .When(x => x.CustomParameters != null && x.CustomParameters.Any());
        }

        private bool BeValidValidationLevel(string? validationLevel)
        {
            if (string.IsNullOrEmpty(validationLevel))
                return true;

            var validLevels = new[] { "Basic", "Standard", "Enhanced", "Comprehensive", "Forensic" };
            return validLevels.Contains(validationLevel, StringComparer.OrdinalIgnoreCase);
        }

        private bool BeValidValidationRules(List<string>? rules)
        {
            if (rules == null)
                return true;

            var validRules = new[]
            {
                "file_size", "file_type", "magic_number", "entropy", "hash_check",
                "malware_scan", "signature_check", "metadata_extraction", "format_validation",
                "content_analysis", "archive_scan", "embedded_files", "suspicious_patterns"
            };

            return rules.All(rule => validRules.Contains(rule, StringComparer.OrdinalIgnoreCase));
        }

        private bool NotExceedMaxRuleCount(List<string>? rules)
        {
            if (rules == null)
                return true;

            return rules.Count <= 20; // Maximum 20 validation rules
        }

        private bool BeValidCustomParameters(Dictionary<string, object>? parameters)
        {
            if (parameters == null)
                return true;

            return parameters.All(kvp =>
            {
                // Key validation
                if (string.IsNullOrWhiteSpace(kvp.Key) || 
                    kvp.Key.Length > 50 ||
                    !Regex.IsMatch(kvp.Key, @"^[a-zA-Z0-9_]+$"))
                    return false;

                // Value validation - must be simple types
                if (kvp.Value == null)
                    return true;

                var type = kvp.Value.GetType();
                return type.IsPrimitive || type == typeof(string) || type == typeof(DateTime);
            });
        }

        private bool NotExceedMaxParameterSize(Dictionary<string, object>? parameters)
        {
            if (parameters == null)
                return true;

            var maxSize = 2048; // 2KB limit for custom parameters
            var approximateSize = parameters.Sum(kvp =>
                kvp.Key.Length + (kvp.Value?.ToString()?.Length ?? 0));

            return approximateSize <= maxSize;
        }
    }

    /// <summary>
    /// Validator for batch file operations with concurrency limits
    /// </summary>
    public class FileBatchRequestValidator : AbstractValidator<FileBatchRequest>
    {
        private readonly FileStorageOptions _fileStorageOptions;
        private readonly SecurityOptions _securityOptions;
        private readonly ForensicsOptions _forensicsOptions;

        public FileBatchRequestValidator(
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
            // Files collection validation
            RuleFor(x => x.Files)
                .NotNull()
                .WithMessage("Files collection cannot be null")
                .NotEmpty()
                .WithMessage("At least one file must be provided")
                .Must(NotExceedMaxBatchSize)
                .WithMessage($"Batch cannot exceed {_fileStorageOptions.MaxBatchSize} files")
                .Must(NotExceedTotalSizeLimit)
                .WithMessage($"Total batch size cannot exceed {_fileStorageOptions.MaxBatchSizeMB} MB")
                .Must(AllFilesHaveValidNames)
                .WithMessage("One or more files have invalid names")
                .Must(AllFilesHaveValidExtensions)
                .WithMessage("One or more files have unsupported extensions")
                .Must(NoDuplicateFileNames)
                .WithMessage("Batch contains duplicate file names");

            // Description validation
            RuleFor(x => x.Description)
                .MaximumLength(500)
                .WithMessage("Description cannot exceed 500 characters")
                .Must(NotContainMaliciousContent)
                .WithMessage("Description contains potentially harmful content")
                .When(x => !string.IsNullOrEmpty(x.Description));

            // Parallel processing validation
            RuleFor(x => x.ParallelLimit)
                .InclusiveBetween(1, 10)
                .WithMessage("Parallel limit must be between 1 and 10")
                .LessThanOrEqualTo(_securityOptions.MaxConcurrentUploads)
                .WithMessage($"Parallel limit cannot exceed system maximum of {_securityOptions.MaxConcurrentUploads}");

            // Validation level validation
            RuleFor(x => x.ValidationLevel)
                .MaximumLength(20)
                .WithMessage("Validation level cannot exceed 20 characters")
                .Must(BeValidValidationLevel)
                .WithMessage("Invalid validation level specified");

            // Tags validation
            RuleFor(x => x.Tags)
                .Must(BeValidTags)
                .WithMessage("Tags contain invalid characters or format")
                .Must(NotExceedMaxTagCount)
                .WithMessage($"Cannot exceed {_forensicsOptions.MaxTagsPerFile} tags")
                .When(x => x.Tags != null && x.Tags.Any());

            // Common metadata validation
            RuleFor(x => x.CommonMetadata)
                .Must(BeValidMetadata)
                .WithMessage("Common metadata contains invalid data")
                .Must(NotExceedMaxMetadataSize)
                .WithMessage("Common metadata exceeds maximum size")
                .When(x => x.CommonMetadata != null && x.CommonMetadata.Any());
        }

        private bool NotExceedMaxBatchSize(List<IFormFile>? files)
        {
            if (files == null)
                return false;

            var maxBatchSize = _fileStorageOptions.MaxBatchSize;
            return files.Count <= maxBatchSize;
        }

        private bool NotExceedTotalSizeLimit(List<IFormFile>? files)
        {
            if (files == null)
                return false;

            var maxBatchSizeBytes = _fileStorageOptions.MaxBatchSizeMB * 1024L * 1024L;
            var totalSize = files.Sum(f => f?.Length ?? 0);
            return totalSize <= maxBatchSizeBytes;
        }

        private bool AllFilesHaveValidNames(List<IFormFile>? files)
        {
            if (files == null)
                return false;

            return files.All(file =>
            {
                if (file == null || string.IsNullOrEmpty(file.FileName))
                    return false;

                var fileName = file.FileName;
                
                // Check length
                if (fileName.Length > 255)
                    return false;

                // Check for invalid characters
                var invalidChars = Path.GetInvalidFileNameChars();
                return !fileName.Any(c => invalidChars.Contains(c));
            });
        }

        private bool AllFilesHaveValidExtensions(List<IFormFile>? files)
        {
            if (files == null)
                return false;

            var allowedExtensions = _fileStorageOptions.AllowedExtensions ?? new[]
            {
                ".exe", ".dll", ".bin", ".img", ".vmdk", ".vdi", ".vhd",
                ".log", ".txt", ".csv", ".json", ".xml", ".pcap", ".cap",
                ".evtx", ".reg", ".mem", ".raw", ".dd", ".e01", ".l01"
            };

            return files.All(file =>
            {
                if (file == null || string.IsNullOrEmpty(file.FileName))
                    return false;

                var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
                return allowedExtensions.Contains(extension);
            });
        }

        private bool NoDuplicateFileNames(List<IFormFile>? files)
        {
            if (files == null)
                return false;

            var fileNames = files
                .Where(f => f != null && !string.IsNullOrEmpty(f.FileName))
                .Select(f => f.FileName.ToLowerInvariant())
                .ToList();

            return fileNames.Count == fileNames.Distinct().Count();
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

        private bool BeValidValidationLevel(string validationLevel)
        {
            if (string.IsNullOrEmpty(validationLevel))
                return true;

            var validLevels = new[] { "Basic", "Standard", "Enhanced", "Comprehensive", "Forensic" };
            return validLevels.Contains(validationLevel, StringComparer.OrdinalIgnoreCase);
        }

        private bool BeValidTags(List<string>? tags)
        {
            if (tags == null)
                return true;

            return tags.All(tag =>
                !string.IsNullOrWhiteSpace(tag) &&
                tag.Length >= 2 &&
                tag.Length <= 50 &&
                Regex.IsMatch(tag, @"^[a-zA-Z0-9_-]+$"));
        }

        private bool NotExceedMaxTagCount(List<string>? tags)
        {
            if (tags == null)
                return true;

            var maxTags = _forensicsOptions.MaxTagsPerFile;
            return tags.Count <= maxTags;
        }

        private bool BeValidMetadata(Dictionary<string, object>? metadata)
        {
            if (metadata == null)
                return true;

            return metadata.All(kvp =>
            {
                if (string.IsNullOrWhiteSpace(kvp.Key) || kvp.Key.Length > 100)
                    return false;

                if (kvp.Value == null)
                    return true;

                var valueStr = kvp.Value.ToString();
                return valueStr != null && valueStr.Length <= 500;
            });
        }

        private bool NotExceedMaxMetadataSize(Dictionary<string, object>? metadata)
        {
            if (metadata == null)
                return true;

            var maxSize = 5120; // 5KB limit for common metadata
            var approximateSize = metadata.Sum(kvp =>
                kvp.Key.Length + (kvp.Value?.ToString()?.Length ?? 0));

            return approximateSize <= maxSize;
        }
    }

    /// <summary>
    /// Validator for batch validation requests
    /// </summary>
    public class FileBatchValidationRequestValidator : AbstractValidator<FileBatchValidationRequest>
    {
        private readonly SecurityOptions _securityOptions;

        public FileBatchValidationRequestValidator(IOptions<SecurityOptions> securityOptions)
        {
            _securityOptions = securityOptions?.Value ?? throw new ArgumentNullException(nameof(securityOptions));

            SetupValidationRules();
        }

        private void SetupValidationRules()
        {
            // File IDs validation
            RuleFor(x => x.FileIds)
                .NotNull()
                .WithMessage("File IDs collection cannot be null")
                .NotEmpty()
                .WithMessage("At least one file ID must be provided")
                .Must(NotExceedMaxBatchSize)
                .WithMessage("Batch validation cannot exceed maximum allowed files")
                .Must(NotContainDuplicateIds)
                .WithMessage("File IDs cannot contain duplicates")
                .Must(AllValidGuids)
                .WithMessage("All file IDs must be valid GUIDs");

            // Validation level validation
            RuleFor(x => x.ValidationLevel)
                .MaximumLength(20)
                .WithMessage("Validation level cannot exceed 20 characters")
                .Must(BeValidValidationLevel)
                .WithMessage("Invalid validation level specified");

            // Parallel processing validation
            RuleFor(x => x.ParallelLimit)
                .InclusiveBetween(1, 10)
                .WithMessage("Parallel limit must be between 1 and 10")
                .LessThanOrEqualTo(_securityOptions.MaxConcurrentUploads)
                .WithMessage($"Parallel limit cannot exceed system maximum of {_securityOptions.MaxConcurrentUploads}");

            // Validation parameters validation
            RuleFor(x => x.ValidationParameters)
                .Must(BeValidValidationParameters)
                .WithMessage("Validation parameters contain invalid data")
                .Must(NotExceedMaxParameterSize)
                .WithMessage("Validation parameters exceed maximum size")
                .When(x => x.ValidationParameters != null && x.ValidationParameters.Any());
        }

        private bool NotExceedMaxBatchSize(List<Guid>? fileIds)
        {
            if (fileIds == null)
                return false;

            return fileIds.Count <= 100; // Maximum 100 files per batch validation
        }

        private bool NotContainDuplicateIds(List<Guid>? fileIds)
        {
            if (fileIds == null)
                return false;

            return fileIds.Count == fileIds.Distinct().Count();
        }

        private bool AllValidGuids(List<Guid>? fileIds)
        {
            if (fileIds == null)
                return false;

            return fileIds.All(id => id != Guid.Empty);
        }

        private bool BeValidValidationLevel(string validationLevel)
        {
            if (string.IsNullOrEmpty(validationLevel))
                return true;

            var validLevels = new[] { "Basic", "Standard", "Enhanced", "Comprehensive", "Forensic" };
            return validLevels.Contains(validationLevel, StringComparer.OrdinalIgnoreCase);
        }

        private bool BeValidValidationParameters(Dictionary<string, object>? parameters)
        {
            if (parameters == null)
                return true;

            return parameters.All(kvp =>
            {
                if (string.IsNullOrWhiteSpace(kvp.Key) || kvp.Key.Length > 50)
                    return false;

                if (kvp.Value == null)
                    return true;

                var type = kvp.Value.GetType();
                return type.IsPrimitive || type == typeof(string) || type == typeof(DateTime);
            });
        }

        private bool NotExceedMaxParameterSize(Dictionary<string, object>? parameters)
        {
            if (parameters == null)
                return true;

            var maxSize = 2048; // 2KB limit
            var approximateSize = parameters.Sum(kvp =>
                kvp.Key.Length + (kvp.Value?.ToString()?.Length ?? 0));

            return approximateSize <= maxSize;
        }
    }

    /// <summary>
    /// Validator for file quarantine requests
    /// </summary>
    public class FileQuarantineRequestValidator : AbstractValidator<FileQuarantineRequest>
    {
        public FileQuarantineRequestValidator()
        {
            SetupValidationRules();
        }

        private void SetupValidationRules()
        {
            // Reason validation
            RuleFor(x => x.Reason)
                .NotEmpty()
                .WithMessage("Quarantine reason is required")
                .MaximumLength(500)
                .WithMessage("Reason cannot exceed 500 characters")
                .Must(NotContainMaliciousContent)
                .WithMessage("Reason contains potentially harmful content");

            // Duration validation
            RuleFor(x => x.Duration)
                .Must(BeValidDuration)
                .WithMessage("Quarantine duration must be between 1 hour and 1 year")
                .When(x => x.Duration.HasValue);

            // Severity validation
            RuleFor(x => x.Severity)
                .MaximumLength(20)
                .WithMessage("Severity cannot exceed 20 characters")
                .Must(BeValidSeverity)
                .WithMessage("Invalid severity level specified");

            // Notes validation
            RuleFor(x => x.Notes)
                .MaximumLength(1000)
                .WithMessage("Notes cannot exceed 1000 characters")
                .Must(NotContainMaliciousContent)
                .WithMessage("Notes contain potentially harmful content")
                .When(x => !string.IsNullOrEmpty(x.Notes));

            // User validation
            RuleFor(x => x.QuarantinedBy)
                .MaximumLength(100)
                .WithMessage("User identifier cannot exceed 100 characters")
                .Must(BeValidUserIdentifier)
                .WithMessage("Invalid user identifier format")
                .When(x => !string.IsNullOrEmpty(x.QuarantinedBy));
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

        private bool BeValidDuration(TimeSpan? duration)
        {
            if (!duration.HasValue)
                return true;

            var minDuration = TimeSpan.FromHours(1);
            var maxDuration = TimeSpan.FromDays(365);

            return duration.Value >= minDuration && duration.Value <= maxDuration;
        }

        private bool BeValidSeverity(string severity)
        {
            if (string.IsNullOrEmpty(severity))
                return true;

            var validSeverities = new[] { "Low", "Medium", "High", "Critical" };
            return validSeverities.Contains(severity, StringComparer.OrdinalIgnoreCase);
        }

        private bool BeValidUserIdentifier(string? userIdentifier)
        {
            if (string.IsNullOrEmpty(userIdentifier))
                return true;

            // Basic validation for user identifier format
            return Regex.IsMatch(userIdentifier, @"^[a-zA-Z0-9@._-]+$");
        }
    }
}