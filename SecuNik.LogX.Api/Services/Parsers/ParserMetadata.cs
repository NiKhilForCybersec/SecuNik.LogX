using System.Text.Json;

namespace SecuNik.LogX.Api.Services.Parsers
{
    public class ParserMetadata
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Author { get; set; } = string.Empty;
        public List<string> SupportedExtensions { get; set; } = new();
        public List<string> SupportedMimeTypes { get; set; } = new();
        public Dictionary<string, object> Configuration { get; set; } = new();
        public List<string> Dependencies { get; set; } = new();
        public List<string> Capabilities { get; set; } = new();
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        
        public static ParserMetadata FromJson(string json)
        {
            try
            {
                return JsonSerializer.Deserialize<ParserMetadata>(json) ?? new ParserMetadata();
            }
            catch
            {
                return new ParserMetadata();
            }
        }
        
        public string ToJson()
        {
            try
            {
                return JsonSerializer.Serialize(this, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });
            }
            catch
            {
                return "{}";
            }
        }
        
        public bool SupportsExtension(string extension)
        {
            if (string.IsNullOrEmpty(extension)) return false;
            return SupportedExtensions.Contains(extension.ToLowerInvariant());
        }
        
        public bool SupportsMimeType(string mimeType)
        {
            if (string.IsNullOrEmpty(mimeType)) return false;
            return SupportedMimeTypes.Contains(mimeType.ToLowerInvariant());
        }
        
        public void AddCapability(string capability)
        {
            if (!string.IsNullOrEmpty(capability) && !Capabilities.Contains(capability))
            {
                Capabilities.Add(capability);
            }
        }
        
        public void RemoveCapability(string capability)
        {
            Capabilities.Remove(capability);
        }
        
        public bool HasCapability(string capability)
        {
            return Capabilities.Contains(capability);
        }
        
        public void AddDependency(string dependency)
        {
            if (!string.IsNullOrEmpty(dependency) && !Dependencies.Contains(dependency))
            {
                Dependencies.Add(dependency);
            }
        }
        
        public void RemoveDependency(string dependency)
        {
            Dependencies.Remove(dependency);
        }
        
        public bool HasDependency(string dependency)
        {
            return Dependencies.Contains(dependency);
        }
        
        public void SetConfiguration(string key, object value)
        {
            Configuration[key] = value;
        }
        
        public T? GetConfiguration<T>(string key, T? defaultValue = default)
        {
            if (!Configuration.TryGetValue(key, out var value))
            {
                return defaultValue;
            }
            
            try
            {
                if (value is JsonElement jsonElement)
                {
                    return JsonSerializer.Deserialize<T>(jsonElement.GetRawText());
                }
                
                if (value is T directValue)
                {
                    return directValue;
                }
                
                // Try to convert
                return (T?)Convert.ChangeType(value, typeof(T));
            }
            catch
            {
                return defaultValue;
            }
        }
        
        public void RemoveConfiguration(string key)
        {
            Configuration.Remove(key);
        }
        
        public bool HasConfiguration(string key)
        {
            return Configuration.ContainsKey(key);
        }
        
        public Dictionary<string, object> GetValidationInfo()
        {
            var info = new Dictionary<string, object>
            {
                ["has_name"] = !string.IsNullOrEmpty(Name),
                ["has_description"] = !string.IsNullOrEmpty(Description),
                ["has_version"] = !string.IsNullOrEmpty(Version),
                ["has_author"] = !string.IsNullOrEmpty(Author),
                ["supported_extensions_count"] = SupportedExtensions.Count,
                ["supported_mime_types_count"] = SupportedMimeTypes.Count,
                ["capabilities_count"] = Capabilities.Count,
                ["dependencies_count"] = Dependencies.Count,
                ["configuration_keys_count"] = Configuration.Count
            };
            
            return info;
        }
        
        public List<string> Validate()
        {
            var errors = new List<string>();
            
            if (string.IsNullOrWhiteSpace(Name))
            {
                errors.Add("Parser name is required");
            }
            
            if (string.IsNullOrWhiteSpace(Version))
            {
                errors.Add("Parser version is required");
            }
            
            if (SupportedExtensions.Count == 0)
            {
                errors.Add("At least one supported extension is required");
            }
            
            // Validate extension format
            foreach (var extension in SupportedExtensions)
            {
                if (!extension.StartsWith("."))
                {
                    errors.Add($"Extension '{extension}' should start with a dot");
                }
            }
            
            // Validate version format (basic check)
            if (!string.IsNullOrEmpty(Version))
            {
                var versionParts = Version.Split('.');
                if (versionParts.Length < 2 || versionParts.Length > 4)
                {
                    errors.Add("Version should be in format 'major.minor[.patch[.build]]'");
                }
                
                foreach (var part in versionParts)
                {
                    if (!int.TryParse(part, out _))
                    {
                        errors.Add($"Version part '{part}' is not a valid number");
                        break;
                    }
                }
            }
            
            return errors;
        }
        
        public ParserMetadata Clone()
        {
            return new ParserMetadata
            {
                Name = Name,
                Description = Description,
                Version = Version,
                Author = Author,
                SupportedExtensions = new List<string>(SupportedExtensions),
                SupportedMimeTypes = new List<string>(SupportedMimeTypes),
                Configuration = new Dictionary<string, object>(Configuration),
                Dependencies = new List<string>(Dependencies),
                Capabilities = new List<string>(Capabilities),
                CreatedAt = CreatedAt,
                UpdatedAt = DateTime.UtcNow
            };
        }
    }
}