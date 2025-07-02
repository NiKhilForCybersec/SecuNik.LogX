using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecuNikLogX.API.Data.Migrations
{
    /// <summary>
    /// Initial Entity Framework migration for forensics database schema
    /// Creates all required tables, indexes, and constraints for SecuNik LogX platform
    /// </summary>
    public partial class InitialCreate : Migration
    {
        /// <summary>
        /// Create forensics database schema with optimized structure for evidence analysis
        /// </summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Create Analyses table for forensics investigation tracking
            migrationBuilder.CreateTable(
                name: "Analyses",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    FilePath = table.Column<string>(type: "TEXT COLLATE NOCASE", maxLength: 1000, nullable: false),
                    FileHash = table.Column<string>(type: "TEXT COLLATE NOCASE", maxLength: 128, nullable: false),
                    Status = table.Column<string>(type: "TEXT COLLATE NOCASE", maxLength: 50, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false, defaultValueSql: "datetime('now')"),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: false, defaultValueSql: "datetime('now')"),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Analyses", x => x.Id);
                });

            // Create Rules table for YARA and Sigma rule definitions
            migrationBuilder.CreateTable(
                name: "Rules",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Type = table.Column<string>(type: "TEXT COLLATE NOCASE", maxLength: 50, nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false, defaultValue: true),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false, defaultValueSql: "datetime('now')"),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: false, defaultValueSql: "datetime('now')"),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Rules", x => x.Id);
                });

            // Create Parsers table for custom parser definitions
            migrationBuilder.CreateTable(
                name: "Parsers",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    FileType = table.Column<string>(type: "TEXT COLLATE NOCASE", maxLength: 50, nullable: false),
                    IsCompiled = table.Column<bool>(type: "INTEGER", nullable: false, defaultValue: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false, defaultValueSql: "datetime('now')"),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: false, defaultValueSql: "datetime('now')"),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Parsers", x => x.Id);
                });

            // Create IOCs table for Indicators of Compromise extracted from evidence
            migrationBuilder.CreateTable(
                name: "IOCs",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Type = table.Column<string>(type: "TEXT COLLATE NOCASE", maxLength: 50, nullable: false),
                    Value = table.Column<string>(type: "TEXT COLLATE NOCASE", maxLength: 500, nullable: false),
                    ThreatLevel = table.Column<string>(type: "TEXT COLLATE NOCASE", maxLength: 20, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false, defaultValueSql: "datetime('now')"),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: false, defaultValueSql: "datetime('now')"),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IOCs", x => x.Id);
                });

            // Create MITREMappings table for MITRE ATT&CK framework mappings
            migrationBuilder.CreateTable(
                name: "MITREMappings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    TechniqueId = table.Column<string>(type: "TEXT COLLATE NOCASE", maxLength: 20, nullable: false),
                    TacticId = table.Column<string>(type: "TEXT COLLATE NOCASE", maxLength: 20, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false, defaultValueSql: "datetime('now')"),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: false, defaultValueSql: "datetime('now')"),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MITREMappings", x => x.Id);
                });

            // Create junction table for Analysis-MITRE many-to-many relationship
            migrationBuilder.CreateTable(
                name: "AnalysisMITRE",
                columns: table => new
                {
                    AnalysisId = table.Column<int>(type: "INTEGER", nullable: false),
                    MITREId = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AnalysisMITRE", x => new { x.AnalysisId, x.MITREId });
                    table.ForeignKey(
                        name: "FK_AnalysisMITRE_Analyses_AnalysisId",
                        column: x => x.AnalysisId,
                        principalTable: "Analyses",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AnalysisMITRE_MITREMappings_MITREId",
                        column: x => x.MITREId,
                        principalTable: "MITREMappings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            // Create junction table for Rule-Analysis many-to-many relationship
            migrationBuilder.CreateTable(
                name: "RuleAnalysis",
                columns: table => new
                {
                    RuleId = table.Column<int>(type: "INTEGER", nullable: false),
                    AnalysisId = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuleAnalysis", x => new { x.RuleId, x.AnalysisId });
                    table.ForeignKey(
                        name: "FK_RuleAnalysis_Analyses_AnalysisId",
                        column: x => x.AnalysisId,
                        principalTable: "Analyses",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RuleAnalysis_Rules_RuleId",
                        column: x => x.RuleId,
                        principalTable: "Rules",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            // Create performance indexes for forensics query optimization

            // Analysis table indexes for file path and hash lookups
            migrationBuilder.CreateIndex(
                name: "IX_Analysis_FilePath",
                table: "Analyses",
                column: "FilePath");

            migrationBuilder.CreateIndex(
                name: "IX_Analysis_FileHash",
                table: "Analyses",
                column: "FileHash");

            migrationBuilder.CreateIndex(
                name: "IX_Analysis_CreatedAt",
                table: "Analyses",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_Analysis_Status",
                table: "Analyses",
                column: "Status");

            // IOC table indexes for threat intelligence queries
            migrationBuilder.CreateIndex(
                name: "IX_IOC_Type",
                table: "IOCs",
                column: "Type");

            migrationBuilder.CreateIndex(
                name: "IX_IOC_Value",
                table: "IOCs",
                column: "Value");

            migrationBuilder.CreateIndex(
                name: "IX_IOC_ThreatLevel",
                table: "IOCs",
                column: "ThreatLevel");

            // Rule table indexes for rule management queries
            migrationBuilder.CreateIndex(
                name: "IX_Rule_Type",
                table: "Rules",
                column: "Type");

            migrationBuilder.CreateIndex(
                name: "IX_Rule_IsActive",
                table: "Rules",
                column: "IsActive");

            // MITRE table indexes for framework mapping queries
            migrationBuilder.CreateIndex(
                name: "IX_MITRE_TechniqueId",
                table: "MITREMappings",
                column: "TechniqueId");

            migrationBuilder.CreateIndex(
                name: "IX_MITRE_TacticId",
                table: "MITREMappings",
                column: "TacticId");

            // Parser table indexes for file type processing
            migrationBuilder.CreateIndex(
                name: "IX_Parser_FileType",
                table: "Parsers",
                column: "FileType");

            migrationBuilder.CreateIndex(
                name: "IX_Parser_IsCompiled",
                table: "Parsers",
                column: "IsCompiled");

            // Junction table indexes for relationship queries
            migrationBuilder.CreateIndex(
                name: "IX_AnalysisMITRE_MITREId",
                table: "AnalysisMITRE",
                column: "MITREId");

            migrationBuilder.CreateIndex(
                name: "IX_RuleAnalysis_AnalysisId",
                table: "RuleAnalysis",
                column: "AnalysisId");

            // Add composite indexes for complex forensics queries
            migrationBuilder.CreateIndex(
                name: "IX_Analyses_Status_CreatedAt",
                table: "Analyses",
                columns: new[] { "Status", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_IOCs_Type_ThreatLevel",
                table: "IOCs",
                columns: new[] { "Type", "ThreatLevel" });

            migrationBuilder.CreateIndex(
                name: "IX_Rules_Type_IsActive",
                table: "Rules",
                columns: new[] { "Type", "IsActive" });

            // Add foreign key relationships for data integrity

            // IOCs to Analysis relationship (if AnalysisId column exists)
            // Note: This would be added when proper entity models are defined in Batch 3
            
            // Parsers to Analysis relationship (if ParserId column exists)
            // Note: This would be added when proper entity models are defined in Batch 3

            // Enable SQLite performance optimizations
            migrationBuilder.Sql("PRAGMA journal_mode=WAL;");
            migrationBuilder.Sql("PRAGMA synchronous=NORMAL;");
            migrationBuilder.Sql("PRAGMA foreign_keys=ON;");
            migrationBuilder.Sql("PRAGMA case_sensitive_like=OFF;");
            migrationBuilder.Sql("PRAGMA optimize;");
        }

        /// <summary>
        /// Rollback forensics database schema to previous state
        /// </summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Drop junction tables first to avoid foreign key constraint violations
            migrationBuilder.DropTable(
                name: "AnalysisMITRE");

            migrationBuilder.DropTable(
                name: "RuleAnalysis");

            // Drop main entity tables
            migrationBuilder.DropTable(
                name: "IOCs");

            migrationBuilder.DropTable(
                name: "MITREMappings");

            migrationBuilder.DropTable(
                name: "Parsers");

            migrationBuilder.DropTable(
                name: "Rules");

            migrationBuilder.DropTable(
                name: "Analyses");

            // Reset SQLite optimizations to defaults
            migrationBuilder.Sql("PRAGMA journal_mode=DELETE;");
            migrationBuilder.Sql("PRAGMA synchronous=FULL;");
        }
    }
}