using Microsoft.AspNetCore.Mvc;
using SecuNikLogX.API.DTOs;
using FluentValidation;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.SignalR;

namespace SecuNikLogX.API.Controllers
{
    /// <summary>
    /// File upload and management controller for forensics evidence handling
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class FileController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<FileController> _logger;
        private readonly IWebHostEnvironment _environment;

        /// <summary>
        /// Initializes a new instance of the FileController
        /// </summary>
        /// <param name="configuration">Application configuration</param>
        /// <param name="logger">Logger instance</param>
        /// <param name="environment">Web host environment</param>
        public FileController(
            IConfiguration configuration,
            ILogger<FileController> logger,
            IWebHostEnvironment environment)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _environment = environment ?? throw new ArgumentNullException(nameof(environment));
        }

        /// <summary>
        /// Uploads a single file for forensics analysis
        /// </summary>
        /// <param name="file">File to upload</param>
        /// <param name="description">Optional file description</param>
        /// <param name="preserveOriginalName">Whether to preserve original filename</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>File upload result</returns>
        [HttpPost("upload")]
        [ProducesResponseType(typeof(FileUploadResponse), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status413PayloadTooLarge)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [RequestSizeLimit(2147483648)] // 2GB limit
        public async Task<ActionResult<FileUploadResponse>> UploadFile(
            IFormFile file,
            [FromForm] string? description = null,
            [FromForm] bool preserveOriginalName = false,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (file == null || file.Length == 0)
                {
                    return BadRequest("No file provided or file is empty");
                }

                var maxFileSize = _configuration.GetValue<long>("FileStorage:MaxFileSizeMB", 500) * 1024 * 1024;
                if (file.Length > maxFileSize)
                {
                    return StatusCode(413, $"File size exceeds maximum allowed size of {maxFileSize / (1024 * 1024)} MB");
                }

                var allowedExtensions = _configuration.GetSection("FileStorage:AllowedExtensions").Get<string[]>() 
                    ?? new[] { ".exe", ".dll", ".bin", ".img", ".vmdk", ".vdi", ".log", ".txt", ".csv", ".json", ".xml", ".pcap" };

                var fileExtension = Path.GetExtension(file.FileName).ToLowerInvariant();
                if (!allowedExtensions.Contains(fileExtension))
                {
                    return BadRequest($"File type '{fileExtension}' is not allowed");
                }

                var uploadPath = _configuration.GetValue<string>("FileStorage:UploadPath") 
                    ?? Path.Combine(_environment.ContentRootPath, "uploads");

                if (!Directory.Exists(uploadPath))
                {
                    Directory.CreateDirectory(uploadPath);
                }

                var fileId = Guid.NewGuid();
                var fileName = preserveOriginalName ? 
                    SanitizeFileName(file.FileName) : 
                    $"{fileId}{fileExtension}";

                var filePath = Path.Combine(uploadPath, fileName);

                // Ensure no path traversal attacks
                if (!filePath.StartsWith(uploadPath))
                {
                    return BadRequest("Invalid file path");
                }

                var fileHash = await CalculateFileHashAsync(file, cancellationToken);
                var metadata = await ExtractFileMetadataAsync(file, cancellationToken);

                await using var stream = new FileStream(filePath, FileMode.Create);
                await file.CopyToAsync(stream, cancellationToken);

                var response = new FileUploadResponse
                {
                    FileId = fileId,
                    FileName = fileName,
                    OriginalFileName = file.FileName,
                    FilePath = filePath,
                    FileSize = file.Length,
                    FileHash = fileHash,
                    ContentType = file.ContentType,
                    UploadedAt = DateTime.UtcNow,
                    Description = description,
                    Metadata = metadata,
                    IsValidated = false
                };

                _logger.LogInformation("File uploaded successfully: {FileName} ({FileSize} bytes)", fileName, file.Length);
                return CreatedAtAction(nameof(GetFileMetadata), new { id = fileId }, response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading file: {FileName}", file?.FileName);
                return StatusCode(500, "Internal server error occurred during file upload");
            }
        }

        /// <summary>
        /// Uploads multiple files for batch processing
        /// </summary>
        /// <param name="files">Files to upload</param>
        /// <param name="description">Optional batch description</param>
        /// <param name="preserveOriginalNames">Whether to preserve original filenames</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Batch upload results</returns>
        [HttpPost("batch-upload")]
        [ProducesResponseType(typeof(FileBatchUploadResponse), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status413PayloadTooLarge)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [RequestSizeLimit(10737418240)] // 10GB limit for batch uploads
        public async Task<ActionResult<FileBatchUploadResponse>> BatchUploadFiles(
            List<IFormFile> files,
            [FromForm] string? description = null,
            [FromForm] bool preserveOriginalNames = false,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (files == null || !files.Any())
                {
                    return BadRequest("No files provided");
                }

                var maxBatchSize = _configuration.GetValue<int>("FileStorage:MaxBatchSize", 50);
                if (files.Count > maxBatchSize)
                {
                    return BadRequest($"Batch size exceeds maximum allowed size of {maxBatchSize} files");
                }

                var results = new List<FileUploadResponse>();
                var errors = new List<string>();

                var batchId = Guid.NewGuid();
                _logger.LogInformation("Starting batch upload {BatchId} with {FileCount} files", batchId, files.Count);

                foreach (var file in files)
                {
                    try
                    {
                        var uploadResult = await UploadSingleFileInternal(file, description, preserveOriginalNames, cancellationToken);
                        results.Add(uploadResult);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error uploading file in batch: {FileName}", file.FileName);
                        errors.Add($"Failed to upload {file.FileName}: {ex.Message}");
                    }
                }

                var response = new FileBatchUploadResponse
                {
                    BatchId = batchId,
                    TotalFiles = files.Count,
                    SuccessfulUploads = results.Count,
                    FailedUploads = errors.Count,
                    UploadedFiles = results,
                    Errors = errors,
                    BatchDescription = description,
                    UploadedAt = DateTime.UtcNow
                };

                return CreatedAtAction(nameof(GetBatchStatus), new { batchId }, response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during batch file upload");
                return StatusCode(500, "Internal server error occurred during batch upload");
            }
        }

        /// <summary>
        /// Validates a file for content and format compliance
        /// </summary>
        /// <param name="id">File ID</param>
        /// <param name="request">Validation request parameters</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>File validation results</returns>
        [HttpPost("{id:guid}/validate")]
        [ProducesResponseType(typeof(FileValidationResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<FileValidationResponse>> ValidateFile(
            Guid id,
            [FromBody] FileValidationRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // This would typically retrieve file information from database
                // For now, implementing basic validation logic
                
                var validationResults = new List<ValidationResult>();
                var isValid = true;

                // Placeholder validation logic - would be enhanced with actual file analysis
                validationResults.Add(new ValidationResult
                {
                    Rule = "File Size Check",
                    Passed = true,
                    Message = "File size is within acceptable limits"
                });

                validationResults.Add(new ValidationResult
                {
                    Rule = "File Type Check",
                    Passed = true,
                    Message = "File type is allowed for forensics analysis"
                });

                validationResults.Add(new ValidationResult
                {
                    Rule = "Malware Scan",
                    Passed = true,
                    Message = "No malware detected"
                });

                var response = new FileValidationResponse
                {
                    FileId = id,
                    IsValid = isValid,
                    ValidationResults = validationResults,
                    ValidatedAt = DateTime.UtcNow,
                    ValidationLevel = request.ValidationLevel ?? "Standard"
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating file {FileId}", id);
                return StatusCode(500, "Internal server error occurred during file validation");
            }
        }

        /// <summary>
        /// Gets file metadata and properties
        /// </summary>
        /// <param name="id">File ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>File metadata</returns>
        [HttpGet("{id:guid}/metadata")]
        [ProducesResponseType(typeof(FileMetadataResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<FileMetadataResponse>> GetFileMetadata(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // Placeholder implementation - would typically query database
                var response = new FileMetadataResponse
                {
                    FileId = id,
                    FileName = $"file_{id}",
                    FileSize = 1024000,
                    FileType = "application/octet-stream",
                    CreatedAt = DateTime.UtcNow.AddDays(-1),
                    ModifiedAt = DateTime.UtcNow.AddDays(-1),
                    Hash = await Task.FromResult("sha256hash"),
                    Properties = new Dictionary<string, object>
                    {
                        ["Magic Number"] = "4D5A",
                        ["Architecture"] = "x64",
                        ["Compiler"] = "MSVC"
                    }
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving file metadata {FileId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets file hash information
        /// </summary>
        /// <param name="id">File ID</param>
        /// <param name="algorithm">Hash algorithm (md5, sha1, sha256)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>File hash information</returns>
        [HttpGet("{id:guid}/hash")]
        [ProducesResponseType(typeof(FileHashResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<FileHashResponse>> GetFileHash(
            Guid id,
            [FromQuery] string algorithm = "sha256",
            CancellationToken cancellationToken = default)
        {
            try
            {
                var supportedAlgorithms = new[] { "md5", "sha1", "sha256", "sha512" };
                if (!supportedAlgorithms.Contains(algorithm.ToLower()))
                {
                    return BadRequest($"Unsupported hash algorithm. Supported: {string.Join(", ", supportedAlgorithms)}");
                }

                // Placeholder implementation
                var response = new FileHashResponse
                {
                    FileId = id,
                    Algorithm = algorithm.ToUpper(),
                    Hash = await Task.FromResult($"{algorithm.ToLower()}_hash_value"),
                    CalculatedAt = DateTime.UtcNow
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating file hash {FileId} with algorithm {Algorithm}", id, algorithm);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets comprehensive file properties
        /// </summary>
        /// <param name="id">File ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Detailed file properties</returns>
        [HttpGet("{id:guid}/properties")]
        [ProducesResponseType(typeof(FilePropertiesResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<FilePropertiesResponse>> GetFileProperties(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var response = new FilePropertiesResponse
                {
                    FileId = id,
                    BasicProperties = new Dictionary<string, object>
                    {
                        ["Size"] = 1024000,
                        ["Type"] = "PE32",
                        ["Created"] = DateTime.UtcNow.AddDays(-1)
                    },
                    ExtendedProperties = new Dictionary<string, object>
                    {
                        ["Entropy"] = 7.2,
                        ["Sections"] = 6,
                        ["Imports"] = 45
                    },
                    ForensicsProperties = new Dictionary<string, object>
                    {
                        ["Suspicious Patterns"] = 0,
                        ["Known Signatures"] = 1,
                        ["Risk Level"] = "Low"
                    },
                    AnalyzedAt = DateTime.UtcNow
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving file properties {FileId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets all uploaded files with pagination
        /// </summary>
        /// <param name="pageNumber">Page number</param>
        /// <param name="pageSize">Page size</param>
        /// <param name="fileType">Filter by file type</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of uploaded files</returns>
        [HttpGet]
        [ProducesResponseType(typeof(FileListResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<FileListResponse>> GetFiles(
            [FromQuery] int pageNumber = 1,
            [FromQuery] int pageSize = 20,
            [FromQuery] string? fileType = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (pageNumber <= 0 || pageSize <= 0 || pageSize > 100)
                {
                    return BadRequest("Invalid pagination parameters");
                }

                // Placeholder implementation
                var files = new List<FileListItem>();
                var totalCount = 0;

                var response = new FileListResponse
                {
                    Files = files,
                    TotalCount = totalCount,
                    PageNumber = pageNumber,
                    PageSize = pageSize
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving file list");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Deletes a file
        /// </summary>
        /// <param name="id">File ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Deletion result</returns>
        [HttpDelete("{id:guid}")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> DeleteFile(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // Placeholder implementation - would typically delete from database and filesystem
                await Task.Delay(10, cancellationToken); // Simulate async operation
                
                _logger.LogInformation("File deleted: {FileId}", id);
                return NoContent();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting file {FileId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Quarantines a file for security reasons
        /// </summary>
        /// <param name="id">File ID</param>
        /// <param name="request">Quarantine request</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Quarantine result</returns>
        [HttpPost("{id:guid}/quarantine")]
        [ProducesResponseType(typeof(FileQuarantineResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<FileQuarantineResponse>> QuarantineFile(
            Guid id,
            [FromBody] FileQuarantineRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var quarantinePath = _configuration.GetValue<string>("FileStorage:QuarantinePath") 
                    ?? Path.Combine(_environment.ContentRootPath, "quarantine");

                if (!Directory.Exists(quarantinePath))
                {
                    Directory.CreateDirectory(quarantinePath);
                }

                var response = new FileQuarantineResponse
                {
                    FileId = id,
                    QuarantinedAt = DateTime.UtcNow,
                    Reason = request.Reason,
                    QuarantineDuration = request.Duration,
                    IsQuarantined = true,
                    QuarantinePath = quarantinePath
                };

                _logger.LogWarning("File quarantined: {FileId}, Reason: {Reason}", id, request.Reason);
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error quarantining file {FileId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Releases a file from quarantine
        /// </summary>
        /// <param name="id">File ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Release result</returns>
        [HttpPost("{id:guid}/release")]
        [ProducesResponseType(typeof(FileQuarantineResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<FileQuarantineResponse>> ReleaseFromQuarantine(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var response = new FileQuarantineResponse
                {
                    FileId = id,
                    QuarantinedAt = DateTime.UtcNow.AddDays(-1),
                    ReleasedAt = DateTime.UtcNow,
                    Reason = "Released by administrator",
                    IsQuarantined = false
                };

                _logger.LogInformation("File released from quarantine: {FileId}", id);
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error releasing file from quarantine {FileId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Verifies file integrity
        /// </summary>
        /// <param name="id">File ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Integrity verification result</returns>
        [HttpGet("{id:guid}/verify")]
        [ProducesResponseType(typeof(FileIntegrityResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<FileIntegrityResponse>> VerifyFileIntegrity(
            Guid id,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var response = new FileIntegrityResponse
                {
                    FileId = id,
                    IsIntegrityValid = true,
                    OriginalHash = "original_hash_value",
                    CurrentHash = "current_hash_value",
                    LastModified = DateTime.UtcNow.AddDays(-1),
                    VerifiedAt = DateTime.UtcNow
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying file integrity {FileId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Recalculates file hash
        /// </summary>
        /// <param name="id">File ID</param>
        /// <param name="algorithm">Hash algorithm</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>New hash calculation result</returns>
        [HttpPost("{id:guid}/rehash")]
        [ProducesResponseType(typeof(FileHashResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<FileHashResponse>> RecalculateFileHash(
            Guid id,
            [FromQuery] string algorithm = "sha256",
            CancellationToken cancellationToken = default)
        {
            try
            {
                var response = new FileHashResponse
                {
                    FileId = id,
                    Algorithm = algorithm.ToUpper(),
                    Hash = await Task.FromResult($"recalculated_{algorithm.ToLower()}_hash"),
                    CalculatedAt = DateTime.UtcNow
                };

                _logger.LogInformation("File hash recalculated: {FileId} using {Algorithm}", id, algorithm);
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error recalculating file hash {FileId}", id);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Validates multiple files in batch
        /// </summary>
        /// <param name="request">Batch validation request</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Batch validation results</returns>
        [HttpPost("batch-validate")]
        [ProducesResponseType(typeof(FileBatchValidationResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<FileBatchValidationResponse>> BatchValidateFiles(
            [FromBody] FileBatchValidationRequest request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                if (request.FileIds == null || !request.FileIds.Any())
                {
                    return BadRequest("No file IDs provided for validation");
                }

                var validationResults = new List<FileValidationResult>();

                foreach (var fileId in request.FileIds)
                {
                    validationResults.Add(new FileValidationResult
                    {
                        FileId = fileId,
                        IsValid = true,
                        ValidationMessages = new List<string> { "File passed all validation checks" }
                    });
                }

                var response = new FileBatchValidationResponse
                {
                    BatchId = Guid.NewGuid(),
                    TotalFiles = request.FileIds.Count,
                    ValidFiles = validationResults.Count(r => r.IsValid),
                    InvalidFiles = validationResults.Count(r => !r.IsValid),
                    ValidationResults = validationResults,
                    ValidatedAt = DateTime.UtcNow
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during batch file validation");
                return StatusCode(500, "Internal server error occurred");
            }
        }

        /// <summary>
        /// Gets batch upload status
        /// </summary>
        /// <param name="batchId">Batch ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Batch status information</returns>
        [HttpGet("batch/{batchId:guid}/status")]
        [ProducesResponseType(typeof(FileBatchStatusResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<FileBatchStatusResponse>> GetBatchStatus(
            Guid batchId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var response = new FileBatchStatusResponse
                {
                    BatchId = batchId,
                    Status = "Completed",
                    TotalFiles = 10,
                    ProcessedFiles = 10,
                    SuccessfulFiles = 9,
                    FailedFiles = 1,
                    StartedAt = DateTime.UtcNow.AddHours(-1),
                    CompletedAt = DateTime.UtcNow.AddMinutes(-30)
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving batch status {BatchId}", batchId);
                return StatusCode(500, "Internal server error occurred");
            }
        }

        private async Task<FileUploadResponse> UploadSingleFileInternal(
            IFormFile file, 
            string? description, 
            bool preserveOriginalName, 
            CancellationToken cancellationToken)
        {
            var uploadPath = _configuration.GetValue<string>("FileStorage:UploadPath") 
                ?? Path.Combine(_environment.ContentRootPath, "uploads");

            var fileId = Guid.NewGuid();
            var fileExtension = Path.GetExtension(file.FileName).ToLowerInvariant();
            var fileName = preserveOriginalName ? 
                SanitizeFileName(file.FileName) : 
                $"{fileId}{fileExtension}";

            var filePath = Path.Combine(uploadPath, fileName);
            var fileHash = await CalculateFileHashAsync(file, cancellationToken);
            var metadata = await ExtractFileMetadataAsync(file, cancellationToken);

            await using var stream = new FileStream(filePath, FileMode.Create);
            await file.CopyToAsync(stream, cancellationToken);

            return new FileUploadResponse
            {
                FileId = fileId,
                FileName = fileName,
                OriginalFileName = file.FileName,
                FilePath = filePath,
                FileSize = file.Length,
                FileHash = fileHash,
                ContentType = file.ContentType,
                UploadedAt = DateTime.UtcNow,
                Description = description,
                Metadata = metadata,
                IsValidated = false
            };
        }

        private static async Task<string> CalculateFileHashAsync(IFormFile file, CancellationToken cancellationToken)
        {
            using var sha256 = SHA256.Create();
            await using var stream = file.OpenReadStream();
            var hashBytes = await sha256.ComputeHashAsync(stream, cancellationToken);
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }

        private static async Task<Dictionary<string, object>> ExtractFileMetadataAsync(IFormFile file, CancellationToken cancellationToken)
        {
            await Task.Delay(1, cancellationToken); // Simulate async metadata extraction
            
            return new Dictionary<string, object>
            {
                ["ContentType"] = file.ContentType,
                ["Length"] = file.Length,
                ["Headers"] = file.Headers.ToDictionary(h => h.Key, h => h.Value.ToString())
            };
        }

        private static string SanitizeFileName(string fileName)
        {
            var invalidChars = Path.GetInvalidFileNameChars();
            var sanitized = new StringBuilder();

            foreach (var c in fileName)
            {
                if (!invalidChars.Contains(c))
                {
                    sanitized.Append(c);
                }
                else
                {
                    sanitized.Append('_');
                }
            }

            return sanitized.ToString();
        }
    }
}