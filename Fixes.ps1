# PowerShell script to apply LogX project fixes
# Run this from the LogX solution root directory

Write-Host "Applying LogX Project Fixes..." -ForegroundColor Green

# 1. Fix IParser.cs
$iparserPath = "SecuNik.LogX.Core\Interfaces\IParser.cs"
$iparserContent = @'
namespace SecuNik.LogX.Core.Interfaces;

public interface IParser
{
    string Name { get; }
    string Description { get; }
    string Version { get; }
    string[] SupportedExtensions { get; }
    
    Task<bool> CanParseAsync(string filePath, string content);
    Task<ParseResult> ParseAsync(string filePath, string content, CancellationToken cancellationToken = default);
    Task<ValidationResult> ValidateAsync(string content);
    Dictionary<string, object> GetMetadata();
}

public class ParseResult
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public List<LogEvent> Events { get; set; } = new();
    public Dictionary<string, object> Metadata { get; set; } = new();
    public string ParserUsed { get; set; } = string.Empty;
    public int EventsCount { get; set; }
    public TimeSpan ProcessingTime { get; set; }
    public List<string> Warnings { get; set; } = new();
}

public class LogEvent
{
    public DateTime Timestamp { get; set; }
    public string Level { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public Dictionary<string, object> Fields { get; set; } = new();
    public string RawData { get; set; } = string.Empty;
    public long? Offset { get; set; }
    public int? LineNumber { get; set; }
}

public class ValidationResult
{
    public bool IsValid { get; set; }
    public List<string> Errors { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public Dictionary<string, object> Suggestions { get; set; } = new();
    public Dictionary<string, object> Metadata { get; set; } = new();
}
'@

Set-Content -Path $iparserPath -Value $iparserContent -Encoding UTF8
Write-Host "✓ Fixed IParser.cs" -ForegroundColor Green

# 2. Update System.Text.Json version in Core project
$coreProjPath = "SecuNik.LogX.Core\SecuNik.LogX.Core.csproj"
$coreContent = Get-Content $coreProjPath -Raw
$coreContent = $coreContent -replace '<PackageReference Include="System.Text.Json" Version="8.0.1"', '<PackageReference Include="System.Text.Json" Version="8.0.5"'
Set-Content -Path $coreProjPath -Value $coreContent -Encoding UTF8
Write-Host "✓ Updated System.Text.Json in Core project" -ForegroundColor Green

# 3. Update System.Text.Json version and add CodeAnalysis packages in Api project
$apiProjPath = "SecuNik.LogX.Api\SecuNik.LogX.Api.csproj"
$apiContent = Get-Content $apiProjPath -Raw
$apiContent = $apiContent -replace '<PackageReference Include="System.Text.Json" Version="8.0.1"', '<PackageReference Include="System.Text.Json" Version="8.0.5"'

# Add CodeAnalysis packages if not present
if ($apiContent -notmatch 'Microsoft.CodeAnalysis.Workspaces.Common') {
    $insertPoint = $apiContent.IndexOf('<PackageReference Include="Microsoft.CodeAnalysis.CSharp.Scripting"')
    $endOfLine = $apiContent.IndexOf("/>", $insertPoint) + 2
    $newPackages = @"

    <PackageReference Include="Microsoft.CodeAnalysis.Workspaces.Common" Version="4.8.0" />
    <PackageReference Include="Microsoft.CodeAnalysis.CSharp.Workspaces" Version="4.8.0" />
"@
    $apiContent = $apiContent.Insert($endOfLine, $newPackages)
}
Set-Content -Path $apiProjPath -Value $apiContent -Encoding UTF8
Write-Host "✓ Updated Api project packages" -ForegroundColor Green

# 4. Fix AnalysisService.cs
$analysisServicePath = "SecuNik.LogX.Api\Services\Analysis\AnalysisService.cs"
if (Test-Path $analysisServicePath) {
    $content = Get-Content $analysisServicePath -Raw
    
    # Add using statements if not present
    $usingsToAdd = @"
using SecuNik.LogX.Core.Entities;
using SecuNik.LogX.Core.DTOs;
using SecuNik.LogX.Api.Services.Parsers;

// Add this alias to resolve the namespace conflict with Analysis
using Analysis = SecuNik.LogX.Core.Entities.Analysis;

"@
    
    if ($content -notmatch "using Analysis = SecuNik.LogX.Core.Entities.Analysis;") {
        $namespaceIndex = $content.IndexOf("namespace SecuNik.LogX.Api.Services.Analysis")
        if ($namespaceIndex -gt 0) {
            $content = $content.Insert($namespaceIndex, $usingsToAdd)
            Set-Content -Path $analysisServicePath -Value $content -Encoding UTF8
            Write-Host "✓ Fixed AnalysisService.cs" -ForegroundColor Green
        }
    }
}

# 5. Fix AnalysisOrchestrator.cs
$analysisOrchestratorPath = "SecuNik.LogX.Api\Services\Analysis\AnalysisOrchestrator.cs"
if (Test-Path $analysisOrchestratorPath) {
    $content = Get-Content $analysisOrchestratorPath -Raw
    
    if ($content -notmatch "using Analysis = SecuNik.LogX.Core.Entities.Analysis;") {
        $namespaceIndex = $content.IndexOf("namespace SecuNik.LogX.Api.Services.Analysis")
        if ($namespaceIndex -gt 0) {
            $content = $content.Insert($namespaceIndex, $usingsToAdd)
            Set-Content -Path $analysisOrchestratorPath -Value $content -Encoding UTF8
            Write-Host "✓ Fixed AnalysisOrchestrator.cs" -ForegroundColor Green
        }
    }
}

Write-Host "`nAll fixes applied!" -ForegroundColor Green
Write-Host "`nNow running clean, restore, and build..." -ForegroundColor Yellow

# Clean, restore and build
dotnet clean
dotnet restore
dotnet build

Write-Host "`nDone!" -ForegroundColor Green