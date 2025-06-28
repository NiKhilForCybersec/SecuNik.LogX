using Microsoft.AspNetCore.Mvc;
using SecuNik.LogX.Core.DTOs;
using SecuNik.LogX.Core.Entities;
using SecuNik.LogX.Api.Services.Parsers;
using SecuNik.LogX.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace SecuNik.LogX.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ParserController : ControllerBase
    {
        private readonly ParserFactory _parserFactory;
        private readonly CustomParserLoader _customParserLoader;
        private readonly LogXDbContext _dbContext;
        private readonly ILogger<ParserController> _logger;
        
        public ParserController(
            ParserFactory parserFactory,
            CustomParserLoader customParserLoader,
            LogXDbContext dbContext,
            ILogger<ParserController> logger)
        {
            _parserFactory = parserFactory;
            _customParserLoader = customParserLoader;
            _dbContext = dbContext;
            _logger = logger;
        }
        
        /// <summary>
        /// Get all available parsers
        /// </summary>
        [HttpGet]
        public async Task<ActionResult<List<ParserDto>>> GetParsers(
            [FromQuery] string? type = null,
            [FromQuery] bool? enabled = null,
            [FromQuery] string? extension = null)
        {
            try
            {
                var query = _dbContext.Parsers.AsQueryable();
                
                if (!string.IsNullOrEmpty(type))
                {
                    query = query.Where(p => p.Type == type);
                }
                
                if (enabled.HasValue)
                {
                    query = query.Where(p => p.IsEnabled == enabled.Value);
                }
                
                if (!string.IsNullOrEmpty(extension))
                {
                    query = query.Where(p => p.SupportedExtensions.Contains(extension));
                }
                
                var parsers = await query.OrderBy(p => p.Priority).ToListAsync();
                
                var parserDtos = parsers.Select(p => new ParserDto
                {
                    Id = p.Id,
                    Name = p.Name,
                    Description = p.Description,
                    Type = p.Type,
                    Version = p.Version,
                    Author = p.Author,
                    CreatedAt = p.CreatedAt,
                    UpdatedAt = p.UpdatedAt,
                    IsEnabled = p.IsEnabled,
                    IsBuiltIn = p.IsBuiltIn,
                    SupportedExtensions = p.GetSupportedExtensionsList(),
                    Priority = p.Priority,
                    UsageCount = p.UsageCount,
                    LastUsed = p.LastUsed,
                    Statistics = new ParserStatisticsDto
                    {
                        TotalFilesProcessed = p.UsageCount,
                        LastUsed = p.LastUsed
                    }
                }).ToList();
                
                return Ok(parserDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting parsers");
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Get parser by ID
        /// </summary>
        [HttpGet("{id}")]
        public async Task<ActionResult<ParserDto>> GetParser(Guid id)
        {
            try
            {
                var parser = await _dbContext.Parsers.FindAsync(id);
                if (parser == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }
                
                var parserDto = new ParserDto
                {
                    Id = parser.Id,
                    Name = parser.Name,
                    Description = parser.Description,
                    Type = parser.Type,
                    Version = parser.Version,
                    Author = parser.Author,
                    CreatedAt = parser.CreatedAt,
                    UpdatedAt = parser.UpdatedAt,
                    IsEnabled = parser.IsEnabled,
                    IsBuiltIn = parser.IsBuiltIn,
                    SupportedExtensions = parser.GetSupportedExtensionsList(),
                    CodeContent = parser.CodeContent,
                    Priority = parser.Priority,
                    UsageCount = parser.UsageCount,
                    LastUsed = parser.LastUsed,
                    Statistics = new ParserStatisticsDto
                    {
                        TotalFilesProcessed = parser.UsageCount,
                        LastUsed = parser.LastUsed
                    }
                };
                
                return Ok(parserDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting parser {ParserId}", id);
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Create a new custom parser
        /// </summary>
        [HttpPost]
        public async Task<ActionResult<ParserDto>> CreateParser([FromBody] CreateParserDto createDto)
        {
            try
            {
                // Validate the parser code if provided
                if (!string.IsNullOrEmpty(createDto.CodeContent))
                {
                    var validationResult = await _customParserLoader.ValidateParserCodeAsync(createDto.CodeContent);
                    if (!validationResult.IsValid)
                    {
                        return BadRequest(new
                        {
                            message = "Parser code validation failed",
                            errors = validationResult.Errors,
                            warnings = validationResult.Warnings
                        });
                    }
                }
                
                var parser = await _parserFactory.RegisterCustomParserAsync(
                    createDto.Name,
                    createDto.Description,
                    createDto.Version,
                    createDto.Author,
                    createDto.SupportedExtensions,
                    createDto.CodeContent ?? string.Empty,
                    createDto.Configuration);
                
                if (parser == null)
                {
                    return BadRequest("Failed to create parser");
                }
                
                var parserDto = new ParserDto
                {
                    Id = parser.Id,
                    Name = parser.Name,
                    Description = parser.Description,
                    Type = parser.Type,
                    Version = parser.Version,
                    Author = parser.Author,
                    CreatedAt = parser.CreatedAt,
                    UpdatedAt = parser.UpdatedAt,
                    IsEnabled = parser.IsEnabled,
                    IsBuiltIn = parser.IsBuiltIn,
                    SupportedExtensions = parser.GetSupportedExtensionsList(),
                    CodeContent = parser.CodeContent,
                    Priority = parser.Priority,
                    UsageCount = parser.UsageCount,
                    LastUsed = parser.LastUsed
                };
                
                return CreatedAtAction(nameof(GetParser), new { id = parser.Id }, parserDto);
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating parser");
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Update an existing parser
        /// </summary>
        [HttpPut("{id}")]
        public async Task<ActionResult<ParserDto>> UpdateParser(Guid id, [FromBody] UpdateParserDto updateDto)
        {
            try
            {
                var parser = await _dbContext.Parsers.FindAsync(id);
                if (parser == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }
                
                if (parser.IsBuiltIn)
                {
                    return BadRequest("Cannot update built-in parsers");
                }
                
                // Validate code if being updated
                if (!string.IsNullOrEmpty(updateDto.CodeContent))
                {
                    var validationResult = await _customParserLoader.ValidateParserCodeAsync(updateDto.CodeContent);
                    if (!validationResult.IsValid)
                    {
                        return BadRequest(new
                        {
                            message = "Parser code validation failed",
                            errors = validationResult.Errors,
                            warnings = validationResult.Warnings
                        });
                    }
                }
                
                // Update fields
                if (!string.IsNullOrEmpty(updateDto.Description))
                    parser.Description = updateDto.Description;
                
                if (!string.IsNullOrEmpty(updateDto.Version))
                    parser.Version = updateDto.Version;
                
                if (updateDto.IsEnabled.HasValue)
                    parser.IsEnabled = updateDto.IsEnabled.Value;
                
                if (updateDto.SupportedExtensions != null)
                    parser.SetSupportedExtensions(updateDto.SupportedExtensions);
                
                if (updateDto.Configuration != null)
                    parser.ConfigurationJson = System.Text.Json.JsonSerializer.Serialize(updateDto.Configuration);
                
                if (!string.IsNullOrEmpty(updateDto.CodeContent))
                {
                    parser.CodeContent = updateDto.CodeContent;
                    // Unload the old version
                    _customParserLoader.UnloadParser(parser.Id);
                }
                
                if (updateDto.Priority.HasValue)
                    parser.Priority = updateDto.Priority.Value;
                
                parser.UpdatedAt = DateTime.UtcNow;
                
                await _dbContext.SaveChangesAsync();
                
                var parserDto = new ParserDto
                {
                    Id = parser.Id,
                    Name = parser.Name,
                    Description = parser.Description,
                    Type = parser.Type,
                    Version = parser.Version,
                    Author = parser.Author,
                    CreatedAt = parser.CreatedAt,
                    UpdatedAt = parser.UpdatedAt,
                    IsEnabled = parser.IsEnabled,
                    IsBuiltIn = parser.IsBuiltIn,
                    SupportedExtensions = parser.GetSupportedExtensionsList(),
                    CodeContent = parser.CodeContent,
                    Priority = parser.Priority,
                    UsageCount = parser.UsageCount,
                    LastUsed = parser.LastUsed
                };
                
                return Ok(parserDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating parser {ParserId}", id);
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Delete a parser
        /// </summary>
        [HttpDelete("{id}")]
        public async Task<ActionResult> DeleteParser(Guid id)
        {
            try
            {
                var success = await _parserFactory.UnregisterParserAsync(id);
                if (!success)
                {
                    return NotFound($"Parser with ID {id} not found");
                }
                
                // Unload from memory
                _customParserLoader.UnloadParser(id);
                
                return NoContent();
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting parser {ParserId}", id);
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Validate parser code
        /// </summary>
        [HttpPost("validate")]
        public async Task<ActionResult> ValidateParser([FromBody] string code)
        {
            try
            {
                var result = await _customParserLoader.ValidateParserCodeAsync(code);
                
                return Ok(new
                {
                    isValid = result.IsValid,
                    errors = result.Errors,
                    warnings = result.Warnings,
                    suggestions = result.Suggestions
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating parser code");
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Test a parser with sample content
        /// </summary>
        [HttpPost("{id}/test")]
        public async Task<ActionResult> TestParser(Guid id, [FromBody] string testContent)
        {
            try
            {
                var parser = await _dbContext.Parsers.FindAsync(id);
                if (parser == null)
                {
                    return NotFound($"Parser with ID {id} not found");
                }
                
                var result = await _customParserLoader.TestParserAsync(parser, testContent);
                
                return Ok(new
                {
                    success = result.Success,
                    errorMessage = result.ErrorMessage,
                    warnings = result.Warnings,
                    processingTime = result.ProcessingTime.TotalMilliseconds,
                    matches = result.Matches
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing parser {ParserId}", id);
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Get parser statistics
        /// </summary>
        [HttpGet("statistics")]
        public async Task<ActionResult> GetParserStatistics()
        {
            try
            {
                var stats = await _parserFactory.GetParserStatisticsAsync();
                var loaderStats = _customParserLoader.GetLoaderStatistics();
                
                return Ok(new
                {
                    parser_stats = stats,
                    loader_stats = loaderStats
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting parser statistics");
                return StatusCode(500, "Internal server error");
            }
        }
        
        /// <summary>
        /// Get best parser for a file
        /// </summary>
        [HttpPost("suggest")]
        public async Task<ActionResult> SuggestParser([FromBody] SuggestParserRequest request)
        {
            try
            {
                var parser = await _parserFactory.GetParserAsync(request.FilePath, request.Content);
                
                if (parser == null)
                {
                    return Ok(new { suggested_parser = (object?)null, message = "No suitable parser found" });
                }
                
                return Ok(new
                {
                    suggested_parser = new
                    {
                        name = parser.Name,
                        description = parser.Description,
                        version = parser.Version,
                        supported_extensions = parser.SupportedExtensions
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error suggesting parser for file {FilePath}", request.FilePath);
                return StatusCode(500, "Internal server error");
            }
        }
    }
    
    public class SuggestParserRequest
    {
        public string FilePath { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
    }
}