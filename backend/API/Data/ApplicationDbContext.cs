using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.Extensions.Options;
using SecuNikLogX.API.Configuration;

namespace SecuNikLogX.API.Data;

/// <summary>
/// Entity Framework Core database context for local SQLite forensics database
/// Manages all forensics data storage and analysis tracking
/// </summary>
public class ApplicationDbContext : DbContext
{
    private readonly DatabaseOptions _databaseOptions;

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
        _databaseOptions = new DatabaseOptions();
    }

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, IOptions<DatabaseOptions> databaseOptions) 
        : base(options)
    {
        _databaseOptions = databaseOptions.Value;
    }

    /// <summary>
    /// Analysis records for forensics investigation tracking
    /// </summary>
    public DbSet<Analysis> Analyses { get; set; } = null!;

    /// <summary>
    /// YARA and Sigma rule definitions for threat detection
    /// </summary>
    public DbSet<Rule> Rules { get; set; } = null!;

    /// <summary>
    /// Custom parser definitions for log processing
    /// </summary>
    public DbSet<Parser> Parsers { get; set; } = null!;

    /// <summary>
    /// Indicators of Compromise extracted from evidence
    /// </summary>
    public DbSet<IOC> IOCs { get; set; } = null!;

    /// <summary>
    /// MITRE ATT&CK framework mappings for threat categorization
    /// </summary>
    public DbSet<MITRE> MITREMappings { get; set; } = null!;

    /// <summary>
    /// Configure SQLite database provider and connection for local forensics storage
    /// </summary>
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            var connectionString = _databaseOptions.ConnectionString;
            if (string.IsNullOrEmpty(connectionString))
            {
                var databasePath = Environment.GetEnvironmentVariable("DATABASE_PATH") ?? "./data/secunik.db";
                connectionString = $"Data Source={databasePath}";
            }

            optionsBuilder.UseSqlite(connectionString, options =>
            {
                options.CommandTimeout(_databaseOptions.CommandTimeout);
            });

            // Enable sensitive data logging for development environments
            if (_databaseOptions.EnableSensitiveDataLogging)
            {
                optionsBuilder.EnableSensitiveDataLogging();
            }

            // Enable detailed error information for debugging
            if (_databaseOptions.EnableDetailedErrors)
            {
                optionsBuilder.EnableDetailedErrors();
            }

            // Configure SQLite-specific options for performance
            optionsBuilder.UseSqlite(connectionString, sqliteOptions =>
            {
                sqliteOptions.CommandTimeout(_databaseOptions.CommandTimeout);
            });
        }
    }

    /// <summary>
    /// Configure entity relationships and database schema for forensics data model
    /// </summary>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure case-insensitive collation for SQLite compatibility
        if (Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite")
        {
            ConfigureSqliteCollation(modelBuilder);
        }

        // Configure global query filters for soft delete functionality
        ConfigureGlobalQueryFilters(modelBuilder);

        // Configure entity relationships and constraints
        ConfigureEntityRelationships(modelBuilder);

        // Configure indexes for forensics query performance
        ConfigurePerformanceIndexes(modelBuilder);

        // Configure timestamp tracking for audit trails
        ConfigureTimestampTracking(modelBuilder);

        // Configure value conversions for SQLite compatibility
        ConfigureValueConversions(modelBuilder);
    }

    /// <summary>
    /// Configure SQLite-specific collation settings for text searches
    /// </summary>
    private static void ConfigureSqliteCollation(ModelBuilder modelBuilder)
    {
        // Configure case-insensitive collation for forensics text searches
        foreach (var entity in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entity.GetProperties())
            {
                if (property.ClrType == typeof(string))
                {
                    property.SetCollation("NOCASE");
                }
            }
        }
    }

    /// <summary>
    /// Configure global query filters for soft delete and active records
    /// </summary>
    private static void ConfigureGlobalQueryFilters(ModelBuilder modelBuilder)
    {
        // Soft delete filter - exclude deleted records from queries
        modelBuilder.Entity<Analysis>().HasQueryFilter(e => !e.IsDeleted);
        modelBuilder.Entity<Rule>().HasQueryFilter(e => !e.IsDeleted);
        modelBuilder.Entity<Parser>().HasQueryFilter(e => !e.IsDeleted);
        modelBuilder.Entity<IOC>().HasQueryFilter(e => !e.IsDeleted);
        modelBuilder.Entity<MITRE>().HasQueryFilter(e => !e.IsDeleted);
    }

    /// <summary>
    /// Configure entity relationships for forensics data integrity
    /// </summary>
    private static void ConfigureEntityRelationships(ModelBuilder modelBuilder)
    {
        // Analysis to IOC relationship (one-to-many)
        modelBuilder.Entity<Analysis>()
            .HasMany<IOC>()
            .WithOne()
            .HasForeignKey("AnalysisId")
            .OnDelete(DeleteBehavior.Cascade);

        // Analysis to MITRE relationship (many-to-many)
        modelBuilder.Entity<Analysis>()
            .HasMany<MITRE>()
            .WithMany()
            .UsingEntity("AnalysisMITRE");

        // Parser to Analysis relationship (one-to-many)
        modelBuilder.Entity<Parser>()
            .HasMany<Analysis>()
            .WithOne()
            .HasForeignKey("ParserId")
            .OnDelete(DeleteBehavior.SetNull);

        // Rule to Analysis relationship (many-to-many)
        modelBuilder.Entity<Rule>()
            .HasMany<Analysis>()
            .WithMany()
            .UsingEntity("RuleAnalysis");
    }

    /// <summary>
    /// Configure database indexes for forensics query performance optimization
    /// </summary>
    private static void ConfigurePerformanceIndexes(ModelBuilder modelBuilder)
    {
        // Analysis performance indexes
        modelBuilder.Entity<Analysis>()
            .HasIndex(a => a.FilePath)
            .HasDatabaseName("IX_Analysis_FilePath");

        modelBuilder.Entity<Analysis>()
            .HasIndex(a => a.FileHash)
            .HasDatabaseName("IX_Analysis_FileHash");

        modelBuilder.Entity<Analysis>()
            .HasIndex(a => a.CreatedAt)
            .HasDatabaseName("IX_Analysis_CreatedAt");

        modelBuilder.Entity<Analysis>()
            .HasIndex(a => a.Status)
            .HasDatabaseName("IX_Analysis_Status");

        // IOC performance indexes
        modelBuilder.Entity<IOC>()
            .HasIndex(i => i.Type)
            .HasDatabaseName("IX_IOC_Type");

        modelBuilder.Entity<IOC>()
            .HasIndex(i => i.Value)
            .HasDatabaseName("IX_IOC_Value");

        modelBuilder.Entity<IOC>()
            .HasIndex(i => i.ThreatLevel)
            .HasDatabaseName("IX_IOC_ThreatLevel");

        // Rule performance indexes
        modelBuilder.Entity<Rule>()
            .HasIndex(r => r.Type)
            .HasDatabaseName("IX_Rule_Type");

        modelBuilder.Entity<Rule>()
            .HasIndex(r => r.IsActive)
            .HasDatabaseName("IX_Rule_IsActive");

        // MITRE performance indexes
        modelBuilder.Entity<MITRE>()
            .HasIndex(m => m.TechniqueId)
            .HasDatabaseName("IX_MITRE_TechniqueId");

        modelBuilder.Entity<MITRE>()
            .HasIndex(m => m.TacticId)
            .HasDatabaseName("IX_MITRE_TacticId");

        // Parser performance indexes
        modelBuilder.Entity<Parser>()
            .HasIndex(p => p.FileType)
            .HasDatabaseName("IX_Parser_FileType");

        modelBuilder.Entity<Parser>()
            .HasIndex(p => p.IsCompiled)
            .HasDatabaseName("IX_Parser_IsCompiled");
    }

    /// <summary>
    /// Configure automatic timestamp tracking for audit and forensics chain of custody
    /// </summary>
    private static void ConfigureTimestampTracking(ModelBuilder modelBuilder)
    {
        // Configure CreatedAt and UpdatedAt for all entities
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            if (entityType.ClrType.GetProperty("CreatedAt") != null)
            {
                modelBuilder.Entity(entityType.ClrType)
                    .Property("CreatedAt")
                    .HasDefaultValueSql("datetime('now')");
            }

            if (entityType.ClrType.GetProperty("UpdatedAt") != null)
            {
                modelBuilder.Entity(entityType.ClrType)
                    .Property("UpdatedAt")
                    .HasDefaultValueSql("datetime('now')");
            }
        }
    }

    /// <summary>
    /// Configure value conversions for SQLite data type compatibility
    /// </summary>
    private static void ConfigureValueConversions(ModelBuilder modelBuilder)
    {
        // Configure DateTime to UTC for consistent forensics timestamps
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entityType.GetProperties())
            {
                if (property.ClrType == typeof(DateTime) || property.ClrType == typeof(DateTime?))
                {
                    property.SetValueConverter(new ValueConverter<DateTime, DateTime>(
                        v => v.ToUniversalTime(),
                        v => DateTime.SpecifyKind(v, DateTimeKind.Utc)
                    ));
                }
            }
        }
    }

    /// <summary>
    /// Override SaveChanges to implement automatic timestamp updates and audit logging
    /// </summary>
    public override int SaveChanges()
    {
        UpdateTimestamps();
        return base.SaveChanges();
    }

    /// <summary>
    /// Override SaveChangesAsync to implement automatic timestamp updates and audit logging
    /// </summary>
    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        UpdateTimestamps();
        return await base.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Update timestamp properties for modified entities
    /// </summary>
    private void UpdateTimestamps()
    {
        var entries = ChangeTracker.Entries()
            .Where(e => e.State == EntityState.Added || e.State == EntityState.Modified);

        foreach (var entry in entries)
        {
            if (entry.Entity.GetType().GetProperty("UpdatedAt") != null)
            {
                entry.Property("UpdatedAt").CurrentValue = DateTime.UtcNow;
            }

            if (entry.State == EntityState.Added && 
                entry.Entity.GetType().GetProperty("CreatedAt") != null)
            {
                entry.Property("CreatedAt").CurrentValue = DateTime.UtcNow;
            }
        }
    }

    /// <summary>
    /// Perform database health check for forensics platform monitoring
    /// </summary>
    public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await Database.ExecuteSqlRawAsync("SELECT 1", cancellationToken);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Get database connection state for monitoring and diagnostics
    /// </summary>
    public string GetConnectionState()
    {
        return Database.GetDbConnection().State.ToString();
    }

    /// <summary>
    /// Optimize database for forensics workload performance
    /// </summary>
    public async Task OptimizeDatabaseAsync()
    {
        if (Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite")
        {
            await Database.ExecuteSqlRawAsync("PRAGMA optimize");
            await Database.ExecuteSqlRawAsync("PRAGMA analysis_limit=1000");
            await Database.ExecuteSqlRawAsync("PRAGMA cache_size=10000");
        }
    }
}

/// <summary>
/// Placeholder entity classes for future batch implementation
/// These will be properly defined in Batch 3: Core Models & Entities
/// </summary>
public class Analysis
{
    public int Id { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string FileHash { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public bool IsDeleted { get; set; }
}

public class Rule
{
    public int Id { get; set; }
    public string Type { get; set; } = string.Empty;
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public bool IsDeleted { get; set; }
}

public class Parser
{
    public int Id { get; set; }
    public string FileType { get; set; } = string.Empty;
    public bool IsCompiled { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public bool IsDeleted { get; set; }
}

public class IOC
{
    public int Id { get; set; }
    public string Type { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string ThreatLevel { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public bool IsDeleted { get; set; }
}

public class MITRE
{
    public int Id { get; set; }
    public string TechniqueId { get; set; } = string.Empty;
    public string TacticId { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public bool IsDeleted { get; set; }
}