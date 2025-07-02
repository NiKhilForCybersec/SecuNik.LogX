# SecuNik LogX - Environment Variables Template
# Local-first digital forensics platform configuration
# Copy this file to .env and update values for your local development environment

# =============================================================================
# FRONTEND CONFIGURATION (Vite)
# =============================================================================

# API Configuration
VITE_API_URL=http://localhost:5000
VITE_API_VERSION=v1
VITE_API_TIMEOUT=30000

# Application Configuration
VITE_APP_NAME=SecuNik LogX
VITE_APP_VERSION=1.0.0
VITE_APP_DESCRIPTION=Local-first Digital Forensics Platform
VITE_ENVIRONMENT=development

# Feature Flags
VITE_ENABLE_AI_ANALYSIS=true
VITE_ENABLE_REAL_TIME_UPDATES=true
VITE_ENABLE_CUSTOM_PARSERS=true
VITE_ENABLE_RULE_MANAGEMENT=true

# UI Configuration
VITE_DEFAULT_THEME=dark
VITE_SIDEBAR_COLLAPSED=false
VITE_MAX_FILE_SIZE=104857600
VITE_SUPPORTED_FILE_TYPES=.log,.txt,.csv,.json,.xml,.evt,.evtx

# Development Configuration
VITE_DEBUG_MODE=true
VITE_LOG_LEVEL=debug
VITE_ENABLE_DEV_TOOLS=true

# =============================================================================
# BACKEND CONFIGURATION (.NET Core)
# =============================================================================

# ASP.NET Core Configuration
ASPNETCORE_ENVIRONMENT=Development
ASPNETCORE_URLS=http://localhost:5000;https://localhost:5001
ASPNETCORE_HTTPS_PORT=5001

# Database Configuration (Local SQLite)
DATABASE_PATH=./data/secunik.db
DATABASE_CONNECTION_TIMEOUT=30
DATABASE_COMMAND_TIMEOUT=60
DATABASE_ENABLE_LOGGING=true

# File Storage Configuration (Local Directories)
UPLOAD_PATH=./uploads
TEMP_PATH=./temp
LOGS_PATH=./logs
BACKUP_PATH=./backups
EVIDENCE_PATH=./evidence
QUARANTINE_PATH=./quarantine

# Analysis Configuration
MAX_ANALYSIS_THREADS=4
MAX_FILE_SIZE_BYTES=104857600
ANALYSIS_TIMEOUT_MINUTES=30
ENABLE_PARALLEL_PROCESSING=true

# Parser Configuration
CUSTOM_PARSERS_PATH=./parsers
PARSER_COMPILATION_TIMEOUT=60
ENABLE_PARSER_CACHING=true
PARSER_MAX_MEMORY_MB=512

# Rule Engine Configuration
YARA_RULES_PATH=./rules/yara
SIGMA_RULES_PATH=./rules/sigma
RULES_AUTO_UPDATE=false
RULES_VALIDATION_STRICT=true

# =============================================================================
# EXTERNAL API CONFIGURATION (Optional)
# =============================================================================

# OpenAI API Configuration (Optional - for AI-powered analysis)
# Get your API key from: https://platform.openai.com/account/api-keys
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4
OPENAI_MAX_TOKENS=2048
OPENAI_TEMPERATURE=0.2
OPENAI_TIMEOUT_SECONDS=60

# VirusTotal API Configuration (Optional - for threat intelligence)
# Get your API key from: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
VIRUSTOTAL_API_URL=https://www.virustotal.com/vtapi/v2
VIRUSTOTAL_RATE_LIMIT_REQUESTS=4
VIRUSTOTAL_RATE_LIMIT_WINDOW=60

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# JWT Configuration (Local Authentication)
JWT_SECRET=your_secure_jwt_secret_key_minimum_32_characters
JWT_ISSUER=SecuNikLogX
JWT_AUDIENCE=SecuNikLogX-Users
JWT_EXPIRE_HOURS=24

# Encryption Configuration (Local Data Protection)
ENCRYPTION_KEY=your_secure_encryption_key_minimum_32_characters
DATA_PROTECTION_KEY_PATH=./keys

# CORS Configuration (Local Development)
CORS_ORIGINS=http://localhost:5173,http://localhost:4173
CORS_ALLOW_CREDENTIALS=true
CORS_MAX_AGE=86400

# Rate Limiting Configuration
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_MINUTES=1
RATE_LIMIT_ENABLE=true

# =============================================================================
# SIGNALR CONFIGURATION (Real-time Updates)
# =============================================================================

# SignalR Real-time Communication
SIGNALR_ENABLED=true
SIGNALR_PATH=/api/hub/analysis
SIGNALR_TRANSPORT=WebSockets,ServerSentEvents
SIGNALR_MAX_CONNECTIONS=100

# Hub Configuration
HUB_ENABLE_DETAILED_ERRORS=true
HUB_CLIENT_TIMEOUT_SECONDS=30
HUB_KEEP_ALIVE_INTERVAL_SECONDS=15

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Serilog Configuration
LOG_LEVEL=Debug
LOG_CONSOLE_ENABLED=true
LOG_FILE_ENABLED=true
LOG_FILE_PATH=./logs/secunik-{Date}.log
LOG_FILE_ROLLING_INTERVAL=Day
LOG_FILE_RETAIN_DAYS=30

# Log Structure
LOG_INCLUDE_SCOPES=true
LOG_INCLUDE_REQUEST_ID=true
LOG_INCLUDE_USER_ID=true
LOG_INCLUDE_MACHINE_NAME=true

# Performance Logging
LOG_PERFORMANCE_ENABLED=true
LOG_SLOW_QUERY_THRESHOLD_MS=1000
LOG_LONG_RUNNING_TASK_THRESHOLD_MS=5000

# =============================================================================
# MONITORING AND HEALTH CHECKS
# =============================================================================

# Health Check Configuration
HEALTH_CHECK_ENABLED=true
HEALTH_CHECK_PATH=/health
HEALTH_CHECK_DETAILED=true
HEALTH_CHECK_CACHE_SECONDS=30

# Performance Monitoring
PERFORMANCE_MONITORING_ENABLED=true
MEMORY_THRESHOLD_MB=1024
CPU_THRESHOLD_PERCENT=80
DISK_THRESHOLD_PERCENT=90

# System Monitoring
MONITOR_FILE_SYSTEM_CHANGES=true
MONITOR_PROCESS_USAGE=true
MONITOR_NETWORK_USAGE=false

# =============================================================================
# DEVELOPMENT AND DEBUGGING
# =============================================================================

# Development Configuration
ENABLE_SWAGGER=true
ENABLE_DETAILED_ERRORS=true
ENABLE_SENSITIVE_DATA_LOGGING=false
ENABLE_DEVELOPER_EXCEPTION_PAGE=true

# Debug Configuration
DEBUG_ENABLE_SQL_LOGGING=true
DEBUG_ENABLE_HTTP_LOGGING=true
DEBUG_ENABLE_PERFORMANCE_COUNTERS=true

# Testing Configuration
ENABLE_TEST_ENDPOINTS=false
TEST_DATA_SEED=false
MOCK_EXTERNAL_APIS=false

# =============================================================================
# CACHE CONFIGURATION
# =============================================================================

# Memory Cache Configuration
CACHE_ENABLED=true
CACHE_DEFAULT_EXPIRATION_MINUTES=60
CACHE_MAX_SIZE_MB=256
CACHE_CLEANUP_INTERVAL_MINUTES=5

# Analysis Results Cache
CACHE_ANALYSIS_RESULTS=true
CACHE_ANALYSIS_EXPIRATION_HOURS=24
CACHE_IOC_RESULTS=true
CACHE_IOC_EXPIRATION_HOURS=6

# =============================================================================
# BACKUP AND RECOVERY
# =============================================================================

# Backup Configuration
BACKUP_ENABLED=true
BACKUP_INTERVAL_HOURS=6
BACKUP_RETENTION_DAYS=30
BACKUP_COMPRESS=true

# Database Backup
DB_BACKUP_ENABLED=true
DB_BACKUP_ON_STARTUP=true
DB_BACKUP_BEFORE_MIGRATION=true

# Evidence Backup
EVIDENCE_BACKUP_ENABLED=true
EVIDENCE_BACKUP_VERIFY_INTEGRITY=true
EVIDENCE_BACKUP_ENCRYPT=true

# =============================================================================
# FORENSICS SPECIFIC CONFIGURATION
# =============================================================================

# Chain of Custody
CHAIN_OF_CUSTODY_ENABLED=true
CHAIN_OF_CUSTODY_REQUIRE_SIGNATURE=true
CHAIN_OF_CUSTODY_LOG_ALL_ACCESS=true

# Evidence Handling
EVIDENCE_HASH_ALGORITHM=SHA256
EVIDENCE_VERIFY_INTEGRITY=true
EVIDENCE_AUTO_QUARANTINE_THREATS=true

# Analysis Configuration
ANALYSIS_PRESERVE_ORIGINAL=true
ANALYSIS_CREATE_WORKING_COPY=true
ANALYSIS_HASH_ALL_FILES=true

# Reporting Configuration
REPORTS_AUTO_GENERATE=true
REPORTS_INCLUDE_METADATA=true
REPORTS_DIGITAL_SIGNATURE=false

# =============================================================================
# NETWORK AND SECURITY
# =============================================================================

# Network Configuration
BIND_ADDRESS=127.0.0.1
BIND_IPV6=false
MAX_REQUEST_SIZE_MB=100
REQUEST_TIMEOUT_SECONDS=300

# Security Headers
SECURITY_HEADERS_ENABLED=true
HSTS_ENABLED=true
CONTENT_SECURITY_POLICY_ENABLED=true
X_FRAME_OPTIONS=DENY

# File Security
SCAN_UPLOADS_FOR_MALWARE=true
QUARANTINE_SUSPICIOUS_FILES=true
ALLOW_EXECUTABLE_UPLOADS=false

# =============================================================================
# NOTES AND INSTRUCTIONS
# =============================================================================

# IMPORTANT: This is a template file. Copy to .env and customize for your environment.
# 
# Required for basic operation:
# - DATABASE_PATH: Path where SQLite database will be created
# - UPLOAD_PATH: Directory for file uploads
# - LOGS_PATH: Directory for application logs
#
# Optional but recommended:
# - OPENAI_API_KEY: For AI-powered analysis features
# - VIRUSTOTAL_API_KEY: For threat intelligence lookups
# - JWT_SECRET: For secure authentication (generate a random 32+ character string)
# - ENCRYPTION_KEY: For data encryption (generate a random 32+ character string)
#
# Local Development:
# - All paths are relative to the application root
# - Directories will be created automatically if they don't exist
# - No cloud dependencies - everything runs locally
# - API keys are optional and only used if provided
#
# Security:
# - Never commit actual API keys or secrets to version control
# - Use strong, unique secrets for JWT and encryption keys
# - Regularly rotate API keys and secrets
# - Keep this file permissions restricted (600 on Unix systems)
#
# Performance:
# - Adjust MAX_ANALYSIS_THREADS based on your CPU cores
# - Increase MAX_FILE_SIZE_BYTES for larger evidence files
# - Monitor memory usage and adjust cache sizes accordingly