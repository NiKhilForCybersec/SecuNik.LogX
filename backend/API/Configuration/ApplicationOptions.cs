using System.ComponentModel.DataAnnotations;

namespace SecuNikLogX.API.Configuration;

/// <summary>
/// Database configuration options for local SQLite forensics database
/// </summary>
public class DatabaseOptions
{
    public const string SectionName = "Database";

    /// <summary>
    /// SQLite database connection string for local forensics data storage
    /// </summary>
    [Required]
    public string ConnectionString { get; set; } = string.Empty;

    /// <summary>
    /// Database provider type (SQLite for local-first operation)
    /// </summary>
    [Required]
    public string Provider { get; set; } = "SQLite";

    /// <summary>
    /// Enable Entity Framework Core sensitive data logging for development
    /// </summary>
    public bool EnableSensitiveDataLogging { get; set; } = false;

    /// <summary>
    /// Enable detailed query logging for performance analysis
    /// </summary>
    public bool EnableDetailedErrors { get; set; } = false;

    /// <summary>
    /// Database command timeout in seconds for large forensics operations
    /// </summary>
    [Range(30, 3600)]
    public int CommandTimeout { get; set; } = 300;

    /// <summary>
    /// Maximum retry attempts for database operations
    /// </summary>
    [Range(1, 10)]
    public int MaxRetryCount { get; set; } = 3;

    /// <summary>
    /// Connection pool size for concurrent forensics analysis
    /// </summary>
    [Range(1, 100)]
    public int MaxPoolSize { get; set; } = 20;

    /// <summary>
    /// Enable automatic database migrations on startup
    /// </summary>
    public bool AutoMigrate { get; set; } = true;
}

/// <summary>
/// Security configuration options for local forensics data protection
/// </summary>
public class SecurityOptions
{
    public const string SectionName = "Security";

    /// <summary>
    /// JWT signing key for local authentication
    /// </summary>
    [Required, MinLength(32)]
    public string JwtSecret { get; set; } = string.Empty;

    /// <summary>
    /// JWT token expiration time in minutes
    /// </summary>
    [Range(15, 1440)]
    public int JwtExpirationMinutes { get; set; } = 60;

    /// <summary>
    /// Data protection encryption key for sensitive forensics data
    /// </summary>
    [Required, MinLength(32)]
    public string EncryptionKey { get; set; } = string.Empty;

    /// <summary>
    /// Salt for password hashing and data protection
    /// </summary>
    [Required, MinLength(16)]
    public string Salt { get; set; } = string.Empty;

    /// <summary>
    /// Enable HTTPS redirection for secure local communication
    /// </summary>
    public bool RequireHttps { get; set; } = true;

    /// <summary>
    /// Enable API key authentication for enhanced security
    /// </summary>
    public bool EnableApiKeyAuth { get; set; } = false;

    /// <summary>
    /// API rate limiting requests per minute
    /// </summary>
    [Range(10, 10000)]
    public int RateLimitPerMinute { get; set; } = 100;

    /// <summary>
    /// Enable request size limits for file uploads
    /// </summary>
    public bool EnableRequestSizeLimits { get; set; } = true;

    /// <summary>
    /// Maximum request body size in bytes for evidence uploads
    /// </summary>
    [Range(1048576, 10737418240)] // 1MB to 10GB
    public long MaxRequestBodySize { get; set; } = 2147483648; // 2GB
}

/// <summary>
/// File storage configuration options for local forensics evidence management
/// </summary>
public class FileStorageOptions
{
    public const string SectionName = "FileStorage";

    /// <summary>
    /// Base path for all local file storage operations
    /// </summary>
    [Required]
    public string BasePath { get; set; } = "./data";

    /// <summary>
    /// Upload directory for incoming evidence files
    /// </summary>
    [Required]
    public string UploadPath { get; set; } = "./uploads";

    /// <summary>
    /// Processed evidence storage directory
    /// </summary>
    [Required]
    public string EvidencePath { get; set; } = "./evidence";

    /// <summary>
    /// Quarantine directory for suspicious files
    /// </summary>
    [Required]
    public string QuarantinePath { get; set; } = "./quarantine";

    /// <summary>
    /// Temporary processing directory
    /// </summary>
    [Required]
    public string TempPath { get; set; } = "./temp";

    /// <summary>
    /// Backup directory for database and evidence preservation
    /// </summary>
    [Required]
    public string BackupPath { get; set; } = "./backups";

    /// <summary>
    /// Maximum individual file size in bytes
    /// </summary>
    [Range(1048576, 10737418240)] // 1MB to 10GB
    public long MaxFileSize { get; set; } = 1073741824; // 1GB

    /// <summary>
    /// Allowed file extensions for evidence processing
    /// </summary>
    public string[] AllowedExtensions { get; set; } = {
        ".log", ".txt", ".csv", ".json", ".xml", ".evtx", ".pcap", ".cap",
        ".mem", ".dmp", ".bin", ".img", ".dd", ".raw", ".e01", ".aff", ".vmdk"
    };

    /// <summary>
    /// Enable automatic file compression for storage optimization
    /// </summary>
    public bool EnableCompression { get; set; } = true;

    /// <summary>
    /// Enable file integrity verification using checksums
    /// </summary>
    public bool EnableIntegrityCheck { get; set; } = true;

    /// <summary>
    /// File retention period in days for temporary files
    /// </summary>
    [Range(1, 365)]
    public int RetentionDays { get; set; } = 30;
}

/// <summary>
/// Logging configuration options for forensics analysis tracking
/// </summary>
public class LoggingOptions
{
    public const string SectionName = "Logging";

    /// <summary>
    /// Base directory for application logs
    /// </summary>
    [Required]
    public string LogPath { get; set; } = "./logs";

    /// <summary>
    /// Minimum log level for application events
    /// </summary>
    [Required]
    public string LogLevel { get; set; } = "Information";

    /// <summary>
    /// Enable structured logging with correlation IDs
    /// </summary>
    public bool EnableStructuredLogging { get; set; } = true;

    /// <summary>
    /// Enable database logging for audit trails
    /// </summary>
    public bool EnableDatabaseLogging { get; set; } = true;

    /// <summary>
    /// Enable performance logging for forensics operations
    /// </summary>
    public bool EnablePerformanceLogging { get; set; } = true;

    /// <summary>
    /// Log file size limit in MB before rotation
    /// </summary>
    [Range(1, 1000)]
    public int FileSizeLimitMB { get; set; } = 100;

    /// <summary>
    /// Number of log files to retain during rotation
    /// </summary>
    [Range(1, 100)]
    public int RetainedFileCountLimit { get; set; } = 31;

    /// <summary>
    /// Enable log compression for long-term storage
    /// </summary>
    public bool EnableCompression { get; set; } = true;

    /// <summary>
    /// Include stack traces in error logs
    /// </summary>
    public bool IncludeStackTrace { get; set; } = true;
}

/// <summary>
/// API configuration options for local forensics platform endpoints
/// </summary>
public class APIOptions
{
    public const string SectionName = "API";

    /// <summary>
    /// Base URL for API endpoints (localhost only)
    /// </summary>
    [Required, Url]
    public string BaseUrl { get; set; } = "https://localhost:5001";

    /// <summary>
    /// API version for endpoint routing
    /// </summary>
    [Required]
    public string Version { get; set; } = "v1";

    /// <summary>
    /// Enable API documentation with Swagger
    /// </summary>
    public bool EnableSwagger { get; set; } = true;

    /// <summary>
    /// Enable CORS for local development
    /// </summary>
    public bool EnableCors { get; set; } = true;

    /// <summary>
    /// Allowed CORS origins for local development
    /// </summary>
    public string[] CorsOrigins { get; set; } = { "http://localhost:5173", "https://localhost:5173" };

    /// <summary>
    /// API request timeout in seconds
    /// </summary>
    [Range(30, 3600)]
    public int RequestTimeoutSeconds { get; set; } = 300;

    /// <summary>
    /// Enable request/response compression
    /// </summary>
    public bool EnableCompression { get; set; } = true;

    /// <summary>
    /// Enable detailed error responses for development
    /// </summary>
    public bool EnableDetailedErrors { get; set; } = false;

    /// <summary>
    /// Maximum concurrent requests for forensics analysis
    /// </summary>
    [Range(1, 1000)]
    public int MaxConcurrentRequests { get; set; } = 50;
}

/// <summary>
/// Performance configuration options for forensics analysis optimization
/// </summary>
public class PerformanceOptions
{
    public const string SectionName = "Performance";

    /// <summary>
    /// Maximum memory usage in MB for analysis operations
    /// </summary>
    [Range(512, 32768)]
    public int MaxMemoryUsageMB { get; set; } = 4096;

    /// <summary>
    /// Number of parallel analysis threads
    /// </summary>
    [Range(1, 32)]
    public int MaxParallelism { get; set; } = Environment.ProcessorCount;

    /// <summary>
    /// Cache size in MB for analysis results
    /// </summary>
    [Range(100, 8192)]
    public int CacheSizeMB { get; set; } = 1024;

    /// <summary>
    /// Cache expiration time in minutes
    /// </summary>
    [Range(5, 1440)]
    public int CacheExpirationMinutes { get; set; } = 60;

    /// <summary>
    /// Enable background processing for large files
    /// </summary>
    public bool EnableBackgroundProcessing { get; set; } = true;

    /// <summary>
    /// Background task queue capacity
    /// </summary>
    [Range(10, 10000)]
    public int BackgroundQueueCapacity { get; set; } = 1000;

    /// <summary>
    /// Database connection pool timeout in seconds
    /// </summary>
    [Range(10, 300)]
    public int ConnectionPoolTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Enable performance monitoring and metrics
    /// </summary>
    public bool EnablePerformanceMonitoring { get; set; } = true;
}

/// <summary>
/// Forensics-specific configuration options for analysis and processing
/// </summary>
public class ForensicsOptions
{
    public const string SectionName = "Forensics";

    /// <summary>
    /// Enable real-time analysis progress reporting
    /// </summary>
    public bool EnableRealTimeProgress { get; set; } = true;

    /// <summary>
    /// Maximum analysis depth for recursive file processing
    /// </summary>
    [Range(1, 20)]
    public int MaxAnalysisDepth { get; set; } = 10;

    /// <summary>
    /// Enable automatic IOC extraction during analysis
    /// </summary>
    public bool EnableAutoIOCExtraction { get; set; } = true;

    /// <summary>
    /// Enable YARA rule scanning on uploaded files
    /// </summary>
    public bool EnableYaraScan { get; set; } = true;

    /// <summary>
    /// YARA rules directory path
    /// </summary>
    [Required]
    public string YaraRulesPath { get; set; } = "./rules/yara";

    /// <summary>
    /// Sigma rules directory path
    /// </summary>
    [Required]
    public string SigmaRulesPath { get; set; } = "./rules/sigma";

    /// <summary>
    /// Custom parsers directory path
    /// </summary>
    [Required]
    public string ParsersPath { get; set; } = "./parsers";

    /// <summary>
    /// Enable MITRE ATT&CK framework mapping
    /// </summary>
    public bool EnableMitreMapping { get; set; } = true;

    /// <summary>
    /// Analysis timeout in minutes for large files
    /// </summary>
    [Range(5, 1440)]
    public int AnalysisTimeoutMinutes { get; set; } = 60;

    /// <summary>
    /// Enable chain of custody logging
    /// </summary>
    public bool EnableChainOfCustody { get; set; } = true;

    /// <summary>
    /// Enable evidence integrity verification
    /// </summary>
    public bool EnableIntegrityVerification { get; set; } = true;
}

/// <summary>
/// Real-time communication configuration for analysis updates
/// </summary>
public class SignalROptions
{
    public const string SectionName = "SignalR";

    /// <summary>
    /// Enable SignalR for real-time communication
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// SignalR hub endpoint path
    /// </summary>
    [Required]
    public string HubPath { get; set; } = "/analysisHub";

    /// <summary>
    /// Connection timeout in seconds
    /// </summary>
    [Range(10, 300)]
    public int ConnectionTimeoutSeconds { get; set; } = 60;

    /// <summary>
    /// Keep alive interval in seconds
    /// </summary>
    [Range(5, 120)]
    public int KeepAliveIntervalSeconds { get; set; } = 15;

    /// <summary>
    /// Maximum message size in bytes
    /// </summary>
    [Range(1024, 1048576)]
    public int MaxMessageSize { get; set; } = 102400; // 100KB

    /// <summary>
    /// Enable MessagePack protocol for performance
    /// </summary>
    public bool EnableMessagePack { get; set; } = true;

    /// <summary>
    /// Maximum concurrent connections
    /// </summary>
    [Range(1, 10000)]
    public int MaxConcurrentConnections { get; set; } = 100;
}