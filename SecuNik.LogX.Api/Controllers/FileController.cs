using Microsoft.AspNetCore.Mvc;
using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Configuration;
using SecuNik.LogX.Core.Constants;
using SecuNik.LogX.Api.Services.Parsers;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

namespace SecuNik.LogX.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class FileController : ControllerBase
    {
        private readonly IStorageService _storageService;
        private readonly ParserFactory _parserFactory;
        private readonly StorageOptions _storageOptions;
        private readonly ILogger<FileController> _logger;
        
        public FileController(
            IStorageService storageService,
            ParserFactory parserFactory,
            IOptions<StorageOptions> storageOptions,
            ILogger<FileController> logger)
        {
            _storageService = storageService;
            _parserFactory = parserFactory;
            _storageOptions = storageOptions.Value;
            _logger = logger;
        }
        
        /// <summary>
        /// Upload a file for analysis
        /// </summary>
        [HttpPost("upload")]
        public async Task<ActionResult> UploadFile(
            IFormFile file,
            [FromForm] bool autoAnalyze = false,
            [FromForm] string? tags = null,
            [FromForm] Guid? preferredParserId = null)
        {
            try
            {
                if (file == null || file.Length == 0)
                {
                    return BadRequest("No file provided");
                }
                
                // Validate file
                var validationResult = ValidateFile(file);
                if (!validationResult.IsValid)
                {
                    return BadRequest(new
                    {
                        message = "File validation failed",
                        errors = validationResult.Errors
                    });
                }
                
                // Generate analysis ID
                var analysisId = Guid.NewGuid();
                
                // Calculate file hash
                var fileHash = await CalculateFileHashAsync(file);
                
                // Save file to storage
                using var stream = file.OpenReadStream();
                var filePath = await _storageService.SaveFileAsync(analysisId, file.FileName, stream);
                
                // Read content for parser detection
                stream.Position = 0;
                var content = await ReadFileContentAsync(stream, file.ContentType);
                
                // Find suitable parser
                var parser = await _parserFactory.GetParserAsync(file.FileName, content, preferredParserId);
                
                // Parse tags
                var tagList = new List<string>();
                if (!string.IsNullOrEmpty(tags))
                {
                    try
                    {
                        tagList = System.Text.Json.JsonSerializer.Deserialize<List<string>>(tags) ?? new List<string>();
                    }
                    catch
                    {
                        tagList = tags.Split(',', StringSplitOptions.RemoveEmptyEntries)
                                     .Select(t => t.Trim())
                                     .ToList();
                    }
                }
                
                var response = new
                {
                    id = analysisId,
                    filename = file.FileName,
                    file_size = file.Length,
                    file_hash = fileHash,
                    content_type = file.ContentType,
                    file_path = filePath,
                    status = "uploaded",
                    parser_detected = parser?.Name,
                    parser_id = preferredParserId,
                    auto_analyze = autoAnalyze,
                    tags = tagList,
                    uploaded_at = DateTime.UtcNow
                };
                
                _logger.LogInformation("File uploaded successfully: {FileName} ({FileSize} bytes) with ID {AnalysisId}",
                    file.FileName, file.Length, analysisId);
                
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading file {FileName}", file?.FileName);
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Get upload status
        /// </summary>
        [HttpGet("upload/{id}/status")]
        public async Task<ActionResult> GetUploadStatus(Guid id)
        {
            try
            {
                // Check if file exists
                var files = await _storageService.ListAnalysisFilesAsync(id);
                
                if (files.Count == 0)
                {
                    return NotFound($"Upload with ID {id} not found");
                }
                
                var response = new
                {
                    id = id,
                    status = "uploaded",
                    files = files,
                    file_count = files.Count
                };
                
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting upload status for {UploadId}", id);
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Download a file
        /// </summary>
        [HttpGet("download/{id}/{filename}")]
        public async Task<ActionResult> DownloadFile(Guid id, string filename)
        {
            try
            {
                var fileExists = await _storageService.FileExistsAsync(id, filename);
                if (!fileExists)
                {
                    return NotFound($"File {filename} not found for analysis {id}");
                }
                
                var stream = await _storageService.GetFileAsync(id, filename);
                var contentType = GetContentType(filename);
                
                return File(stream, contentType, filename);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error downloading file {FileName} for analysis {AnalysisId}", filename, id);
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Delete an uploaded file
        /// </summary>
        [HttpDelete("upload/{id}")]
        public async Task<ActionResult> DeleteUpload(Guid id)
        {
            try
            {
                var success = await _storageService.DeleteAnalysisDirectoryAsync(id);
                if (!success)
                {
                    return NotFound($"Upload with ID {id} not found");
                }
                
                _logger.LogInformation("Deleted upload {UploadId}", id);
                return NoContent();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting upload {UploadId}", id);
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// List all uploads
        /// </summary>
        [HttpGet("uploads")]
        public async Task<ActionResult> ListUploads(
            [FromQuery] int limit = 50,
            [FromQuery] int offset = 0)
        {
            try
            {
                // This is a simplified implementation
                // In a real scenario, you'd want to track uploads in the database
                var storageInfo = await _storageService.GetStorageInfoAsync();
                
                var response = new
                {
                    uploads = new List<object>(), // Would be populated from database
                    total = 0,
                    limit = limit,
                    offset = offset,
                    storage_info = new
                    {
                        total_space = storageInfo.TotalSpace,
                        used_space = storageInfo.UsedSpace,
                        available_space = storageInfo.AvailableSpace,
                        total_files = storageInfo.TotalFiles
                    }
                };
                
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error listing uploads");
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Validate a file without uploading
        /// </summary>
        [HttpPost("validate")]
        public ActionResult ValidateFileUpload(IFormFile file)
        {
            try
            {
                if (file == null || file.Length == 0)
                {
                    return BadRequest("No file provided");
                }
                
                var validationResult = ValidateFile(file);
                
                return Ok(new
                {
                    is_valid = validationResult.IsValid,
                    errors = validationResult.Errors,
                    warnings = validationResult.Warnings,
                    file_info = new
                    {
                        filename = file.FileName,
                        size = file.Length,
                        content_type = file.ContentType,
                        extension = Path.GetExtension(file.FileName),
                        category = FileConstants.GetFileCategory(Path.GetExtension(file.FileName))
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating file {FileName}", file?.FileName);
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Get supported file types
        /// </summary>
        [HttpGet("supported-types")]
        public ActionResult GetSupportedFileTypes()
        {
            try
            {
                var supportedTypes = new
                {
                    extensions = _storageOptions.AllowedExtensions,
                    blocked_extensions = _storageOptions.BlockedExtensions,
                    max_file_size = _storageOptions.MaxFileSize,
                    categories = new
                    {
                        log_files = FileConstants.LogFileExtensions,
                        windows_events = FileConstants.WindowsEventExtensions,
                        network_captures = FileConstants.NetworkCaptureExtensions,
                        archives = FileConstants.ArchiveExtensions,
                        emails = FileConstants.EmailExtensions,
                        structured_data = FileConstants.StructuredDataExtensions,
                        documents = FileConstants.DocumentExtensions,
                        code_files = FileConstants.CodeExtensions,
                        binary_files = FileConstants.BinaryExtensions
                    }
                };
                
                return Ok(supportedTypes);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting supported file types");
                return StatusCode(500, "Internal server error");
            }
        }
        
        private FileValidationResult ValidateFile(IFormFile file)
        {
            var result = new FileValidationResult { IsValid = true };
            
            // Check file size
            if (file.Length > _storageOptions.MaxFileSize)
            {
                result.IsValid = false;
                result.Errors.Add($"File size ({file.Length} bytes) exceeds maximum allowed size ({_storageOptions.MaxFileSize} bytes)");
            }
            
            if (file.Length == 0)
            {
                result.IsValid = false;
                result.Errors.Add("File is empty");
            }
            
            // Check file extension
            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
            
            if (string.IsNullOrEmpty(extension))
            {
                result.Warnings.Add("File has no extension");
            }
            else
            {
                if (_storageOptions.BlockedExtensions.Contains(extension))
                {
                    result.IsValid = false;
                    result.Errors.Add($"File extension {extension} is blocked for security reasons");
                }
                else if (!_storageOptions.AllowedExtensions.Contains(extension))
                {
                    result.Warnings.Add($"File extension {extension} is not in the list of preferred extensions");
                }
            }
            
            // Check filename
            if (string.IsNullOrWhiteSpace(file.FileName))
            {
                result.IsValid = false;
                result.Errors.Add("Filename is required");
            }
            else if (file.FileName.Length > 255)
            {
                result.IsValid = false;
                result.Errors.Add("Filename is too long (maximum 255 characters)");
            }
            
            // Check for potentially dangerous filenames
            var dangerousChars = new[] { '<', '>', ':', '"', '|', '?', '*' };
            if (file.FileName.IndexOfAny(dangerousChars) >= 0)
            {
                result.Warnings.Add("Filename contains potentially dangerous characters");
            }
            
            return result;
        }
        
        private async Task<string> CalculateFileHashAsync(IFormFile file)
        {
            using var stream = file.OpenReadStream();
            using var sha256 = SHA256.Create();
            var hashBytes = await sha256.ComputeHashAsync(stream);
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }
        
        private async Task<string> ReadFileContentAsync(Stream stream, string? contentType)
        {
            try
            {
                // For text files, read as string
                if (contentType?.StartsWith("text/") == true || 
                    contentType == "application/json" ||
                    contentType == "application/xml")
                {
                    using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
                    var content = await reader.ReadToEndAsync();
                    stream.Position = 0;
                    return content;
                }
                
                // For binary files, read a sample
                var buffer = new byte[Math.Min(8192, stream.Length)]; // Read first 8KB
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                stream.Position = 0;
                
                // Try to detect if it's text
                var isText = IsTextContent(buffer, bytesRead);
                if (isText)
                {
                    return Encoding.UTF8.GetString(buffer, 0, bytesRead);
                }
                
                return Convert.ToBase64String(buffer, 0, bytesRead);
            }
            catch
            {
                return string.Empty;
            }
        }
        
        private bool IsTextContent(byte[] buffer, int length)
        {
            // Simple heuristic to detect text content
            var textBytes = 0;
            for (int i = 0; i < length; i++)
            {
                var b = buffer[i];
                if ((b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13) // Printable ASCII + tab, LF, CR
                {
                    textBytes++;
                }
            }
            
            return length > 0 && (double)textBytes / length > 0.7; // 70% text characters
        }
        
        private string GetContentType(string filename)
        {
            var extension = Path.GetExtension(filename).ToLowerInvariant();
            return FileConstants.GetMimeType(extension);
        }
    }
    
    public class FileValidationResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; } = new();
        public List<string> Warnings { get; set; } = new();
    }
}