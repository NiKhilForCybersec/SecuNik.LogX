using System.ComponentModel.DataAnnotations;

namespace SecuNik.LogX.Core.Entities
{
    public class Parser
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();
        
        [Required]
        [MaxLength(100)]
        public string Name { get; set; } = string.Empty;
        
        [MaxLength(500)]
        public string Description { get; set; } = string.Empty;
        
        [Required]
        [MaxLength(50)]
        public string Type { get; set; } = string.Empty; // builtin, custom, script
        
        [Required]
        [MaxLength(100)]
        public string Version { get; set; } = "1.0.0";
        
        [MaxLength(100)]
        public string Author { get; set; } = string.Empty;
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        
        public bool IsEnabled { get; set; } = true;
        
        public bool IsBuiltIn { get; set; } = false;
        
        [Required]
        public string SupportedExtensions { get; set; } = string.Empty; // JSON array
        
        public string? ConfigurationJson { get; set; }
        
        public string? CodeContent { get; set; } // For custom parsers
        
        [MaxLength(255)]
        public string? AssemblyPath { get; set; } // For compiled parsers
        
        [MaxLength(100)]
        public string? ClassName { get; set; } // For compiled parsers
        
        public string? ValidationRules { get; set; } // JSON validation rules
        
        public int Priority { get; set; } = 100; // Lower number = higher priority
        
        public long UsageCount { get; set; } = 0;
        
        public DateTime? LastUsed { get; set; }
        
        // Navigation properties
        public ICollection<Analysis> Analyses { get; set; } = new List<Analysis>();
        
        // Helper methods
        public List<string> GetSupportedExtensionsList()
        {
            try
            {
                return System.Text.Json.JsonSerializer.Deserialize<List<string>>(SupportedExtensions) ?? new List<string>();
            }
            catch
            {
                return new List<string>();
            }
        }
        
        public void SetSupportedExtensions(List<string> extensions)
        {
            SupportedExtensions = System.Text.Json.JsonSerializer.Serialize(extensions);
        }
    }
}