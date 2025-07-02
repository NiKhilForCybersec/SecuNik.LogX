# SecuNik LogX - Project Structure Creation Script
# Creates all folders and empty files at N:\FInal\SecuNik.LogX

# Set the root path
$rootPath = "N:\FInal\SecuNik.LogX"

# Create root directory if it doesn't exist
New-Item -ItemType Directory -Force -Path $rootPath

# Backend structure
$backendDirs = @(
    "$rootPath\backend\API\Controllers",
    "$rootPath\backend\API\Services", 
    "$rootPath\backend\API\Hubs",
    "$rootPath\backend\API\Data\Migrations",
    "$rootPath\backend\API\DTOs",
    "$rootPath\backend\API\Validators",
    "$rootPath\backend\API\Middleware",
    "$rootPath\backend\API\Health",
    "$rootPath\backend\API\Configuration",
    "$rootPath\backend\Core\Models",
    "$rootPath\backend\Core\Interfaces"
)

# Frontend structure
$frontendDirs = @(
    "$rootPath\frontend\src\components",
    "$rootPath\frontend\src\pages",
    "$rootPath\frontend\src\hooks",
    "$rootPath\frontend\src\services",
    "$rootPath\frontend\src\store",
    "$rootPath\frontend\src\contexts",
    "$rootPath\frontend\src\utils",
    "$rootPath\frontend\src\constants",
    "$rootPath\frontend\src\types",
    "$rootPath\frontend\public"
)

# Other directories
$otherDirs = @(
    "$rootPath\shared\config",
    "$rootPath\shared\types",
    "$rootPath\tests\Unit\Backend",
    "$rootPath\tests\Unit\Frontend",
    "$rootPath\tests\Integration",
    "$rootPath\scripts",
    "$rootPath\data",
    "$rootPath\logs",
    "$rootPath\uploads",
    "$rootPath\evidence",
    "$rootPath\quarantine",
    "$rootPath\temp",
    "$rootPath\reports",
    "$rootPath\plugins"
)

# Create all directories
$allDirs = $backendDirs + $frontendDirs + $otherDirs
foreach ($dir in $allDirs) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# Backend files
$backendFiles = @(
    # Controllers
    "$rootPath\backend\API\Controllers\AnalysisController.cs",
    "$rootPath\backend\API\Controllers\FileController.cs",
    "$rootPath\backend\API\Controllers\ParserController.cs",
    "$rootPath\backend\API\Controllers\RuleController.cs",
    "$rootPath\backend\API\Controllers\HealthController.cs",
    
    # Services
    "$rootPath\backend\API\Services\AnalysisService.cs",
    "$rootPath\backend\API\Services\ParserService.cs",
    "$rootPath\backend\API\Services\RuleService.cs",
    "$rootPath\backend\API\Services\AIService.cs",
    "$rootPath\backend\API\Services\IOCExtractor.cs",
    "$rootPath\backend\API\Services\MITREMapper.cs",
    "$rootPath\backend\API\Services\PluginLoader.cs",
    "$rootPath\backend\API\Services\FileProcessingService.cs",
    "$rootPath\backend\API\Services\BackgroundJobService.cs",
    
    # Hubs
    "$rootPath\backend\API\Hubs\AnalysisHub.cs",
    
    # Data
    "$rootPath\backend\API\Data\ApplicationDbContext.cs",
    "$rootPath\backend\API\Data\DbInitializer.cs",
    "$rootPath\backend\API\Data\Migrations\InitialCreate.cs",
    
    # DTOs
    "$rootPath\backend\API\DTOs\AnalysisDto.cs",
    "$rootPath\backend\API\DTOs\FileUploadDto.cs",
    
    # Validators
    "$rootPath\backend\API\Validators\AnalysisValidator.cs",
    "$rootPath\backend\API\Validators\FileUploadValidator.cs",
    
    # Middleware
    "$rootPath\backend\API\Middleware\ErrorHandlingMiddleware.cs",
    "$rootPath\backend\API\Middleware\RequestLoggingMiddleware.cs",
    
    # Health
    "$rootPath\backend\API\Health\DatabaseHealthCheck.cs",
    
    # Configuration
    "$rootPath\backend\API\Configuration\ApplicationOptions.cs",
    
    # Core
    "$rootPath\backend\Core\Models\Analysis.cs",
    "$rootPath\backend\Core\Models\Rule.cs",
    "$rootPath\backend\Core\Models\Parser.cs",
    "$rootPath\backend\Core\Models\IOC.cs",
    "$rootPath\backend\Core\Models\MITRE.cs",
    "$rootPath\backend\Core\Interfaces\IAnalysisService.cs",
    "$rootPath\backend\Core\Interfaces\IParserService.cs",
    "$rootPath\backend\Core\Interfaces\IRuleService.cs",
    "$rootPath\backend\Core\Interfaces\IAIService.cs",
    "$rootPath\backend\Core\Interfaces\IIOCService.cs",
    
    # Root files
    "$rootPath\backend\API\Program.cs",
    "$rootPath\backend\API\appsettings.json",
    "$rootPath\backend\API\appsettings.Development.json",
    "$rootPath\backend\API\SecuNikLogX.API.csproj",
    "$rootPath\backend\SecuNikLogX.sln"
)

# Frontend files
$frontendFiles = @(
    # Components
    "$rootPath\frontend\src\components\Layout.tsx",
    "$rootPath\frontend\src\components\Sidebar.tsx",
    "$rootPath\frontend\src\components\Header.tsx",
    "$rootPath\frontend\src\components\ErrorBoundary.tsx",
    "$rootPath\frontend\src\components\FileUpload.tsx",
    "$rootPath\frontend\src\components\AnalysisCard.tsx",
    "$rootPath\frontend\src\components\SearchFilter.tsx",
    "$rootPath\frontend\src\components\DataTable.tsx",
    "$rootPath\frontend\src\components\ThreatChart.tsx",
    "$rootPath\frontend\src\components\LogViewer.tsx",
    "$rootPath\frontend\src\components\IOCCard.tsx",
    "$rootPath\frontend\src\components\MITREMatrix.tsx",
    "$rootPath\frontend\src\components\ProgressRing.tsx",
    "$rootPath\frontend\src\components\LoadingSkeleton.tsx",
    "$rootPath\frontend\src\components\GlobalSearch.tsx",
    "$rootPath\frontend\src\components\KeyboardShortcuts.tsx",
    "$rootPath\frontend\src\components\AnimatedTransition.tsx",
    
    # Pages
    "$rootPath\frontend\src\pages\Home.tsx",
    "$rootPath\frontend\src\pages\AnalysisPage.tsx",
    "$rootPath\frontend\src\pages\RulePage.tsx",
    "$rootPath\frontend\src\pages\ParserPage.tsx",
    "$rootPath\frontend\src\pages\AnalysisDetail.tsx",
    
    # Hooks
    "$rootPath\frontend\src\hooks\useApi.ts",
    "$rootPath\frontend\src\hooks\useSignalR.ts",
    "$rootPath\frontend\src\hooks\useDebounce.tsx",
    
    # Services
    "$rootPath\frontend\src\services\apiClient.ts",
    "$rootPath\frontend\src\services\analysisAPI.ts",
    
    # Store
    "$rootPath\frontend\src\store\useAppStore.ts",
    "$rootPath\frontend\src\store\useAnalysisStore.ts",
    
    # Contexts
    "$rootPath\frontend\src\contexts\NotificationContext.tsx",
    
    # Utils
    "$rootPath\frontend\src\utils\validation.ts",
    "$rootPath\frontend\src\utils\formatters.ts",
    "$rootPath\frontend\src\utils\iocUtils.ts",
    "$rootPath\frontend\src\utils\mitreMapper.ts",
    
    # Constants
    "$rootPath\frontend\src\constants\theme.ts",
    
    # Types
    "$rootPath\frontend\src\types\env.d.ts",
    
    # Root files
    "$rootPath\frontend\src\main.tsx",
    "$rootPath\frontend\src\App.tsx",
    "$rootPath\frontend\src\index.css",
    "$rootPath\frontend\package.json",
    "$rootPath\frontend\tsconfig.json",
    "$rootPath\frontend\vite.config.ts",
    "$rootPath\frontend\index.html",
    "$rootPath\frontend\.env"
)

# Shared files
$sharedFiles = @(
    "$rootPath\shared\config\constants.ts",
    "$rootPath\shared\types\api.ts"
)

# Test files
$testFiles = @(
    "$rootPath\tests\Unit\Backend\AnalysisServiceTests.cs",
    "$rootPath\tests\Unit\Frontend\ComponentTests.tsx",
    "$rootPath\tests\Integration\ApiTests.cs"
)

# Root files
$rootFiles = @(
    "$rootPath\README.md",
    "$rootPath\.gitignore",
    "$rootPath\.env.example",
    "$rootPath\scripts\setup.sh",
    "$rootPath\scripts\deploy.sh",
    "$rootPath\docker-compose.yml"
)

# Create all files
$allFiles = $backendFiles + $frontendFiles + $sharedFiles + $testFiles + $rootFiles
foreach ($file in $allFiles) {
    New-Item -ItemType File -Force -Path $file | Out-Null
}

Write-Host "✅ SecuNik LogX project structure created successfully!" -ForegroundColor Green
Write-Host "📍 Location: $rootPath" -ForegroundColor Magenta
Write-Host "📁 Total directories created: $($allDirs.Count)" -ForegroundColor Cyan
Write-Host "📄 Total files created: $($allFiles.Count)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Navigate to: cd $rootPath" -ForegroundColor White
Write-Host "2. Open in Visual Studio Code: code $rootPath" -ForegroundColor White
Write-Host "3. Start implementing the code from each batch" -ForegroundColor White