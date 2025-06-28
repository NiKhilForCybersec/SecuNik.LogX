using Microsoft.EntityFrameworkCore;
using SecuNik.LogX.Core.Entities;

namespace SecuNik.LogX.Api.Data
{
    public class LogXDbContext : DbContext
    {
        public LogXDbContext(DbContextOptions<LogXDbContext> options) : base(options)
        {
        }
        
        // DbSets
        public DbSet<Analysis> Analyses { get; set; }
        public DbSet<Parser> Parsers { get; set; }
        public DbSet<Rule> Rules { get; set; }
        public DbSet<RuleMatch> RuleMatches { get; set; }
        
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            
            // Analysis entity configuration
            modelBuilder.Entity<Analysis>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.FileName).IsRequired().HasMaxLength(255);
                entity.Property(e => e.FileHash).IsRequired().HasMaxLength(64);
                entity.Property(e => e.FileType).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Status).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Severity).HasMaxLength(20);
                entity.Property(e => e.Summary).HasColumnType("TEXT");
                entity.Property(e => e.AISummary).HasColumnType("TEXT");
                entity.Property(e => e.ErrorMessage).HasColumnType("TEXT");
                entity.Property(e => e.ParsedDataJson).HasColumnType("TEXT");
                entity.Property(e => e.TimelineJson).HasColumnType("TEXT");
                entity.Property(e => e.IOCsJson).HasColumnType("TEXT");
                entity.Property(e => e.MitreResultsJson).HasColumnType("TEXT");
                entity.Property(e => e.ThreatIntelligenceJson).HasColumnType("TEXT");
                entity.Property(e => e.Tags).HasColumnType("TEXT");
                entity.Property(e => e.Notes).HasColumnType("TEXT");
                
                // Indexes
                entity.HasIndex(e => e.FileHash);
                entity.HasIndex(e => e.Status);
                entity.HasIndex(e => e.UploadTime);
                entity.HasIndex(e => e.ThreatScore);
                entity.HasIndex(e => e.Severity);
                
                // Relationships
                entity.HasOne(e => e.Parser)
                      .WithMany(p => p.Analyses)
                      .HasForeignKey(e => e.ParserId)
                      .OnDelete(DeleteBehavior.SetNull);
                      
                entity.HasMany(e => e.RuleMatches)
                      .WithOne(rm => rm.Analysis)
                      .HasForeignKey(rm => rm.AnalysisId)
                      .OnDelete(DeleteBehavior.Cascade);
            });
            
            // Parser entity configuration
            modelBuilder.Entity<Parser>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Name).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Description).HasMaxLength(500);
                entity.Property(e => e.Type).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Version).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Author).HasMaxLength(100);
                entity.Property(e => e.SupportedExtensions).IsRequired();
                entity.Property(e => e.ConfigurationJson).HasColumnType("TEXT");
                entity.Property(e => e.CodeContent).HasColumnType("TEXT");
                entity.Property(e => e.AssemblyPath).HasMaxLength(255);
                entity.Property(e => e.ClassName).HasMaxLength(100);
                entity.Property(e => e.ValidationRules).HasColumnType("TEXT");
                
                // Indexes
                entity.HasIndex(e => e.Name).IsUnique();
                entity.HasIndex(e => e.Type);
                entity.HasIndex(e => e.IsEnabled);
                entity.HasIndex(e => e.IsBuiltIn);
                
                // Relationships
                entity.HasMany(e => e.Analyses)
                      .WithOne(a => a.Parser)
                      .HasForeignKey(a => a.ParserId)
                      .OnDelete(DeleteBehavior.SetNull);
            });
            
            // Rule entity configuration
            modelBuilder.Entity<Rule>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Name).IsRequired().HasMaxLength(200);
                entity.Property(e => e.Description).HasMaxLength(1000);
                entity.Property(e => e.Type).IsRequired().HasConversion<int>();
                entity.Property(e => e.Category).HasMaxLength(100);
                entity.Property(e => e.Severity).IsRequired().HasConversion<int>();
                entity.Property(e => e.Content).IsRequired().HasColumnType("TEXT");
                entity.Property(e => e.Author).HasMaxLength(100);
                entity.Property(e => e.Tags).HasColumnType("TEXT");
                entity.Property(e => e.References).HasColumnType("TEXT");
                entity.Property(e => e.Metadata).HasColumnType("TEXT");
                entity.Property(e => e.RuleId).HasMaxLength(50);
                entity.Property(e => e.ValidationError).HasColumnType("TEXT");
                
                // Indexes
                entity.HasIndex(e => e.Name);
                entity.HasIndex(e => e.Type);
                entity.HasIndex(e => e.Category);
                entity.HasIndex(e => e.Severity);
                entity.HasIndex(e => e.IsEnabled);
                entity.HasIndex(e => e.IsBuiltIn);
                entity.HasIndex(e => e.RuleId);
                
                // Relationships
                entity.HasMany(e => e.RuleMatches)
                      .WithOne(rm => rm.Rule)
                      .HasForeignKey(rm => rm.RuleId)
                      .OnDelete(DeleteBehavior.Cascade);
            });
            
            // RuleMatch entity configuration
            modelBuilder.Entity<RuleMatch>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.RuleName).IsRequired().HasMaxLength(200);
                entity.Property(e => e.RuleType).IsRequired().HasConversion<int>();
                entity.Property(e => e.Severity).IsRequired().HasConversion<int>();
                entity.Property(e => e.MatchDetails).HasColumnType("TEXT");
                entity.Property(e => e.MatchedContent).HasColumnType("TEXT");
                entity.Property(e => e.Context).HasColumnType("TEXT");
                entity.Property(e => e.MitreAttackIds).HasColumnType("TEXT");
                entity.Property(e => e.AnalystNotes).HasColumnType("TEXT");
                
                // Indexes
                entity.HasIndex(e => e.AnalysisId);
                entity.HasIndex(e => e.RuleId);
                entity.HasIndex(e => e.RuleType);
                entity.HasIndex(e => e.Severity);
                entity.HasIndex(e => e.MatchedAt);
                entity.HasIndex(e => e.Confidence);
                
                // Relationships
                entity.HasOne(e => e.Analysis)
                      .WithMany(a => a.RuleMatches)
                      .HasForeignKey(e => e.AnalysisId)
                      .OnDelete(DeleteBehavior.Cascade);
                      
                entity.HasOne(e => e.Rule)
                      .WithMany(r => r.RuleMatches)
                      .HasForeignKey(e => e.RuleId)
                      .OnDelete(DeleteBehavior.Cascade);
            });
            
            // Seed data
            SeedData(modelBuilder);
        }
        
        private void SeedData(ModelBuilder modelBuilder)
        {
            // Seed built-in parsers
            var builtInParsers = new[]
            {
                new Parser
                {
                    Id = Guid.Parse("11111111-1111-1111-1111-111111111111"),
                    Name = "Windows Event Log Parser",
                    Description = "Parses Windows Event Log files (EVTX/EVT)",
                    Type = "builtin",
                    Version = "1.0.0",
                    Author = "SecuNik Team",
                    IsBuiltIn = true,
                    IsEnabled = true,
                    SupportedExtensions = "[\"evtx\", \"evt\"]",
                    Priority = 10,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                },
                new Parser
                {
                    Id = Guid.Parse("22222222-2222-2222-2222-222222222222"),
                    Name = "JSON Log Parser",
                    Description = "Parses structured JSON log files",
                    Type = "builtin",
                    Version = "1.0.0",
                    Author = "SecuNik Team",
                    IsBuiltIn = true,
                    IsEnabled = true,
                    SupportedExtensions = "[\"json\", \"jsonl\"]",
                    Priority = 20,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                },
                new Parser
                {
                    Id = Guid.Parse("33333333-3333-3333-3333-333333333333"),
                    Name = "CSV Parser",
                    Description = "Parses comma-separated value files",
                    Type = "builtin",
                    Version = "1.0.0",
                    Author = "SecuNik Team",
                    IsBuiltIn = true,
                    IsEnabled = true,
                    SupportedExtensions = "[\"csv\", \"tsv\"]",
                    Priority = 30,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                },
                new Parser
                {
                    Id = Guid.Parse("44444444-4444-4444-4444-444444444444"),
                    Name = "Text Log Parser",
                    Description = "Parses plain text log files with common patterns",
                    Type = "builtin",
                    Version = "1.0.0",
                    Author = "SecuNik Team",
                    IsBuiltIn = true,
                    IsEnabled = true,
                    SupportedExtensions = "[\"log\", \"txt\"]",
                    Priority = 40,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                }
            };
            
            modelBuilder.Entity<Parser>().HasData(builtInParsers);
            
            // Seed built-in rules
            var builtInRules = new[]
            {
                new Rule
                {
                    Id = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                    Name = "Suspicious PowerShell Execution",
                    Description = "Detects suspicious PowerShell command execution patterns",
                    Type = RuleType.Yara,
                    Category = "execution",
                    Severity = ThreatLevel.High,
                    Content = "rule Suspicious_PowerShell { strings: $ps = \"powershell\" $encoded = \"-EncodedCommand\" condition: $ps and $encoded }",
                    Author = "SecuNik Team",
                    IsBuiltIn = true,
                    IsEnabled = true,
                    RuleId = "suspicious_powershell",
                    Priority = 10,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow,
                    Tags = "[\"powershell\", \"execution\", \"suspicious\"]"
                },
                new Rule
                {
                    Id = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                    Name = "Failed Login Attempts",
                    Description = "Detects multiple failed login attempts",
                    Type = RuleType.Sigma,
                    Category = "authentication",
                    Severity = ThreatLevel.Medium,
                    Content = "title: Multiple Failed Logins\ndetection:\n  selection:\n    EventID: 4625\n  condition: selection | count() > 5",
                    Author = "SecuNik Team",
                    IsBuiltIn = true,
                    IsEnabled = true,
                    RuleId = "failed_logins",
                    Priority = 20,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow,
                    Tags = "[\"authentication\", \"bruteforce\", \"login\"]"
                }
            };
            
            modelBuilder.Entity<Rule>().HasData(builtInRules);
        }
        
        public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            // Update timestamps
            var entries = ChangeTracker.Entries()
                .Where(e => e.Entity is Analysis || e.Entity is Parser || e.Entity is Rule)
                .Where(e => e.State == EntityState.Added || e.State == EntityState.Modified);
                
            foreach (var entry in entries)
            {
                if (entry.State == EntityState.Added)
                {
                    if (entry.Entity is Analysis analysis)
                    {
                        analysis.UploadTime = DateTime.UtcNow;
                    }
                    else if (entry.Entity is Parser parser)
                    {
                        parser.CreatedAt = DateTime.UtcNow;
                        parser.UpdatedAt = DateTime.UtcNow;
                    }
                    else if (entry.Entity is Rule rule)
                    {
                        rule.CreatedAt = DateTime.UtcNow;
                        rule.UpdatedAt = DateTime.UtcNow;
                    }
                }
                else if (entry.State == EntityState.Modified)
                {
                    if (entry.Entity is Parser parser)
                    {
                        parser.UpdatedAt = DateTime.UtcNow;
                    }
                    else if (entry.Entity is Rule rule)
                    {
                        rule.UpdatedAt = DateTime.UtcNow;
                    }
                }
            }
            
            return await base.SaveChangesAsync(cancellationToken);
        }
    }
}