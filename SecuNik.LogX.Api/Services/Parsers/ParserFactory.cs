using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.Entities;
using SecuNik.LogX.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace SecuNik.LogX.Api.Services.Parsers
{
    public class ParserFactory
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly LogXDbContext _dbContext;
        private readonly CustomParserLoader _customParserLoader;
        private readonly ILogger<ParserFactory> _logger;
        private readonly Dictionary<string, Type> _builtInParsers;
        
        public ParserFactory(
            IServiceProvider serviceProvider,
            LogXDbContext dbContext,
            CustomParserLoader customParserLoader,
            ILogger<ParserFactory> logger)
        {
            _serviceProvider = serviceProvider;
            _dbContext = dbContext;
            _customParserLoader = customParserLoader;
            _logger = logger;
            _builtInParsers = InitializeBuiltInParsers();
        }
        
        public async Task<IParser?> GetParserAsync(string filePath, string content, Guid? preferredParserId = null)
        {
            try
            {
                var extension = Path.GetExtension(filePath).ToLowerInvariant();
                
                // If a specific parser is preferred, try it first
                if (preferredParserId.HasValue)
                {
                    var preferredParser = await GetParserByIdAsync(preferredParserId.Value);
                    if (preferredParser != null && await preferredParser.CanParseAsync(filePath, content))
                    {
                        _logger.LogInformation("Using preferred parser {ParserName} for file {FilePath}", 
                            preferredParser.Name, filePath);
                        return preferredParser;
                    }
                }
                
                // Get all available parsers for this extension
                var availableParsers = await GetAvailableParsersAsync(extension);
                
                // Test each parser to see if it can handle the content
                foreach (var parser in availableParsers.OrderBy(p => p.Priority))
                {
                    var parserInstance = await CreateParserInstanceAsync(parser);
                    if (parserInstance != null && await parserInstance.CanParseAsync(filePath, content))
                    {
                        _logger.LogInformation("Selected parser {ParserName} for file {FilePath}", 
                            parserInstance.Name, filePath);
                        
                        // Update usage statistics
                        await UpdateParserUsageAsync(parser.Id);
                        
                        return parserInstance;
                    }
                }
                
                _logger.LogWarning("No suitable parser found for file {FilePath} with extension {Extension}", 
                    filePath, extension);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting parser for file {FilePath}", filePath);
                return null;
            }
        }
        
        public async Task<IParser?> GetParserByIdAsync(Guid parserId)
        {
            try
            {
                var parser = await _dbContext.Parsers
                    .FirstOrDefaultAsync(p => p.Id == parserId && p.IsEnabled);
                
                if (parser == null)
                {
                    _logger.LogWarning("Parser with ID {ParserId} not found or disabled", parserId);
                    return null;
                }
                
                return await CreateParserInstanceAsync(parser);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting parser by ID {ParserId}", parserId);
                return null;
            }
        }
        
        public async Task<List<Parser>> GetAvailableParsersAsync(string? extension = null)
        {
            try
            {
                var query = _dbContext.Parsers.Where(p => p.IsEnabled);
                
                if (!string.IsNullOrEmpty(extension))
                {
                    query = query.Where(p => p.SupportedExtensions.Contains(extension));
                }
                
                return await query.OrderBy(p => p.Priority).ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting available parsers");
                return new List<Parser>();
            }
        }
        
        public async Task<IParser?> CreateParserInstanceAsync(Parser parser)
        {
            try
            {
                if (parser.IsBuiltIn)
                {
                    return CreateBuiltInParser(parser);
                }
                else
                {
                    return await _customParserLoader.LoadParserAsync(parser);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating parser instance for {ParserName}", parser.Name);
                return null;
            }
        }
        
        public async Task<List<IParser>> GetAllAvailableParsersAsync()
        {
            var parsers = new List<IParser>();
            
            try
            {
                var parserEntities = await GetAvailableParsersAsync();
                
                foreach (var parserEntity in parserEntities)
                {
                    var parser = await CreateParserInstanceAsync(parserEntity);
                    if (parser != null)
                    {
                        parsers.Add(parser);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all available parsers");
            }
            
            return parsers;
        }
        
        public async Task<ValidationResult> ValidateParserAsync(Parser parser, string testContent)
        {
            try
            {
                var parserInstance = await CreateParserInstanceAsync(parser);
                if (parserInstance == null)
                {
                    return new ValidationResult
                    {
                        IsValid = false,
                        Errors = { "Failed to create parser instance" }
                    };
                }
                
                return await parserInstance.ValidateAsync(testContent);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating parser {ParserName}", parser.Name);
                return new ValidationResult
                {
                    IsValid = false,
                    Errors = { $"Validation error: {ex.Message}" }
                };
            }
        }
        
        private Dictionary<string, Type> InitializeBuiltInParsers()
        {
            return new Dictionary<string, Type>
            {
                ["Windows Event Log Parser"] = typeof(WindowsEventLogParser),
                ["JSON Log Parser"] = typeof(JsonParser),
                ["CSV Parser"] = typeof(CsvParser),
                ["Text Log Parser"] = typeof(TextLogParser)
            };
        }
        
        private IParser? CreateBuiltInParser(Parser parser)
        {
            try
            {
                if (!_builtInParsers.TryGetValue(parser.Name, out var parserType))
                {
                    _logger.LogWarning("Built-in parser type not found for {ParserName}", parser.Name);
                    return null;
                }
                
                return (IParser?)_serviceProvider.GetService(parserType);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating built-in parser {ParserName}", parser.Name);
                return null;
            }
        }
        
        private async Task UpdateParserUsageAsync(Guid parserId)
        {
            try
            {
                var parser = await _dbContext.Parsers.FindAsync(parserId);
                if (parser != null)
                {
                    parser.UsageCount++;
                    parser.LastUsed = DateTime.UtcNow;
                    await _dbContext.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error updating parser usage for {ParserId}", parserId);
                // Don't throw - this is not critical
            }
        }
        
        public async Task<Parser?> RegisterCustomParserAsync(
            string name,
            string description,
            string version,
            string author,
            List<string> supportedExtensions,
            string codeContent,
            Dictionary<string, object>? configuration = null)
        {
            try
            {
                // Check if parser with same name already exists
                var existingParser = await _dbContext.Parsers
                    .FirstOrDefaultAsync(p => p.Name == name);
                
                if (existingParser != null)
                {
                    throw new InvalidOperationException($"Parser with name '{name}' already exists");
                }
                
                var parser = new Parser
                {
                    Name = name,
                    Description = description,
                    Version = version,
                    Author = author,
                    Type = "custom",
                    IsBuiltIn = false,
                    IsEnabled = true,
                    CodeContent = codeContent,
                    Priority = 100, // Default priority for custom parsers
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };
                
                parser.SetSupportedExtensions(supportedExtensions);
                
                if (configuration != null)
                {
                    parser.ConfigurationJson = System.Text.Json.JsonSerializer.Serialize(configuration);
                }
                
                _dbContext.Parsers.Add(parser);
                await _dbContext.SaveChangesAsync();
                
                _logger.LogInformation("Registered custom parser {ParserName}", name);
                return parser;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registering custom parser {ParserName}", name);
                throw;
            }
        }
        
        public async Task<bool> UnregisterParserAsync(Guid parserId)
        {
            try
            {
                var parser = await _dbContext.Parsers.FindAsync(parserId);
                if (parser == null)
                {
                    return false;
                }
                
                if (parser.IsBuiltIn)
                {
                    throw new InvalidOperationException("Cannot unregister built-in parsers");
                }
                
                _dbContext.Parsers.Remove(parser);
                await _dbContext.SaveChangesAsync();
                
                _logger.LogInformation("Unregistered parser {ParserName}", parser.Name);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unregistering parser {ParserId}", parserId);
                throw;
            }
        }
        
        public async Task<Dictionary<string, object>> GetParserStatisticsAsync()
        {
            try
            {
                var stats = new Dictionary<string, object>();
                
                var totalParsers = await _dbContext.Parsers.CountAsync();
                var enabledParsers = await _dbContext.Parsers.CountAsync(p => p.IsEnabled);
                var builtInParsers = await _dbContext.Parsers.CountAsync(p => p.IsBuiltIn);
                var customParsers = await _dbContext.Parsers.CountAsync(p => !p.IsBuiltIn);
                
                var mostUsedParsers = await _dbContext.Parsers
                    .Where(p => p.UsageCount > 0)
                    .OrderByDescending(p => p.UsageCount)
                    .Take(5)
                    .Select(p => new { p.Name, p.UsageCount })
                    .ToListAsync();
                
                stats["total_parsers"] = totalParsers;
                stats["enabled_parsers"] = enabledParsers;
                stats["builtin_parsers"] = builtInParsers;
                stats["custom_parsers"] = customParsers;
                stats["most_used_parsers"] = mostUsedParsers;
                
                return stats;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting parser statistics");
                return new Dictionary<string, object>();
            }
        }
    }
}