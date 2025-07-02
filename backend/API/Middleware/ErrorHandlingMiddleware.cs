using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Text.Json;
using System.Threading.Tasks;
using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecuNik.LogX.Domain.Exceptions;

namespace SecuNik.LogX.API.Middleware
{
    public class ErrorHandlingMiddleware : IMiddleware
    {
        private readonly ILogger<ErrorHandlingMiddleware> _logger;
        private readonly IConfiguration _configuration;
        private readonly ErrorResponseFactory _responseFactory;
        private readonly ErrorMetricsCollector _metricsCollector;
        private readonly bool _includeStackTrace;
        private readonly bool _enableDetailedErrors;

        public ErrorHandlingMiddleware(
            ILogger<ErrorHandlingMiddleware> logger,
            IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
            _responseFactory = new ErrorResponseFactory();
            _metricsCollector = new ErrorMetricsCollector();
            _includeStackTrace = configuration.GetValue<bool>("ErrorHandling:IncludeStackTrace", false);
            _enableDetailedErrors = configuration.GetValue<bool>("ErrorHandling:EnableDetailedErrors", false);
        }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            try
            {
                await next(context);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            var correlationId = GenerateCorrelationId();
            var errorResponse = CreateErrorResponse(exception, correlationId);

            // Log the error with appropriate level
            LogError(exception, correlationId, context);

            // Update metrics
            _metricsCollector.RecordError(exception.GetType().Name, errorResponse.StatusCode);

            // Set response
            context.Response.StatusCode = errorResponse.StatusCode;
            context.Response.ContentType = "application/json";

            // Add correlation ID to response headers
            context.Response.Headers.Add("X-Correlation-Id", correlationId);

            // Write response
            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = true
            };

            var responseJson = JsonSerializer.Serialize(errorResponse, jsonOptions);
            await context.Response.WriteAsync(responseJson);
        }

        private ErrorResponse CreateErrorResponse(Exception exception, string correlationId)
        {
            var (statusCode, errorCode, message) = exception switch
            {
                // Service-specific exceptions
                AnalysisServiceException ase => (
                    DetermineStatusCode(ase),
                    ase.ErrorCode ?? "ANALYSIS_ERROR",
                    SanitizeMessage(ase.Message)
                ),

                ParserServiceException pse => (
                    DetermineStatusCode(pse),
                    pse.ErrorCode ?? "PARSER_ERROR",
                    SanitizeMessage(pse.Message)
                ),

                AIServiceException aise => (
                    DetermineStatusCode(aise),
                    aise.ErrorCode ?? "AI_SERVICE_ERROR",
                    SanitizeMessage(aise.Message)
                ),

                IOCExtractionException iee => (
                    StatusCodes.Status422UnprocessableEntity,
                    "IOC_EXTRACTION_ERROR",
                    "Failed to extract indicators of compromise"
                ),

                MITREMappingException mme => (
                    StatusCodes.Status422UnprocessableEntity,
                    "MITRE_MAPPING_ERROR",
                    "Failed to map MITRE ATT&CK techniques"
                ),

                PluginLoadException ple => (
                    StatusCodes.Status500InternalServerError,
                    "PLUGIN_LOAD_ERROR",
                    "Failed to load or execute plugin"
                ),

                // Entity Framework exceptions
                DbUpdateException dbUpdate => HandleDbUpdateException(dbUpdate),
                DbUpdateConcurrencyException _ => (
                    StatusCodes.Status409Conflict,
                    "CONCURRENCY_ERROR",
                    "The resource was modified by another user"
                ),

                // Validation exceptions
                ValidationException ve => (
                    StatusCodes.Status400BadRequest,
                    "VALIDATION_ERROR",
                    FormatValidationErrors(ve)
                ),

                // OpenAI API exceptions
                HttpRequestException hre when hre.Message.Contains("OpenAI") => (
                    StatusCodes.Status503ServiceUnavailable,
                    "AI_SERVICE_UNAVAILABLE",
                    "AI analysis service is temporarily unavailable"
                ),

                TaskCanceledException when exception.Message.Contains("OpenAI") => (
                    StatusCodes.Status504GatewayTimeout,
                    "AI_SERVICE_TIMEOUT",
                    "AI analysis request timed out"
                ),

                // File operation exceptions
                FileNotFoundException _ => (
                    StatusCodes.Status404NotFound,
                    "FILE_NOT_FOUND",
                    "The requested file was not found"
                ),

                DirectoryNotFoundException _ => (
                    StatusCodes.Status404NotFound,
                    "DIRECTORY_NOT_FOUND",
                    "The specified directory was not found"
                ),

                UnauthorizedAccessException _ => (
                    StatusCodes.Status403Forbidden,
                    "ACCESS_DENIED",
                    "Access to the requested resource is denied"
                ),

                // Security exceptions
                SecurityException _ => (
                    StatusCodes.Status403Forbidden,
                    "SECURITY_VIOLATION",
                    "Security policy prevented this operation"
                ),

                // Parser compilation exceptions
                InvalidOperationException ioe when ioe.Message.Contains("compilation") => (
                    StatusCodes.Status422UnprocessableEntity,
                    "COMPILATION_ERROR",
                    "Parser compilation failed"
                ),

                // Resource exceptions
                OutOfMemoryException _ => (
                    StatusCodes.Status507InsufficientStorage,
                    "INSUFFICIENT_MEMORY",
                    "Insufficient memory to complete the operation"
                ),

                TimeoutException _ => (
                    StatusCodes.Status408RequestTimeout,
                    "OPERATION_TIMEOUT",
                    "The operation timed out"
                ),

                // Argument exceptions
                ArgumentNullException ane => (
                    StatusCodes.Status400BadRequest,
                    "NULL_ARGUMENT",
                    $"Required parameter is missing: {ane.ParamName}"
                ),

                ArgumentException ae => (
                    StatusCodes.Status400BadRequest,
                    "INVALID_ARGUMENT",
                    SanitizeMessage(ae.Message)
                ),

                // Not found exceptions
                KeyNotFoundException _ => (
                    StatusCodes.Status404NotFound,
                    "RESOURCE_NOT_FOUND",
                    "The requested resource was not found"
                ),

                // Rate limiting
                RateLimitExceededException rle => (
                    StatusCodes.Status429TooManyRequests,
                    "RATE_LIMIT_EXCEEDED",
                    rle.Message
                ),

                // Default for unhandled exceptions
                _ => (
                    StatusCodes.Status500InternalServerError,
                    "INTERNAL_ERROR",
                    "An unexpected error occurred"
                )
            };

            var response = _responseFactory.Create(
                statusCode,
                errorCode,
                message,
                correlationId);

            // Add additional details if enabled
            if (_enableDetailedErrors)
            {
                response.Details = new ErrorDetails
                {
                    ExceptionType = exception.GetType().Name,
                    InnerError = exception.InnerException?.Message,
                    Data = FilterSensitiveData(exception.Data)
                };

                if (_includeStackTrace)
                {
                    response.Details.StackTrace = exception.StackTrace;
                }
            }

            return response;
        }

        private (int statusCode, string errorCode, string message) HandleDbUpdateException(DbUpdateException exception)
        {
            var innerException = exception.InnerException;

            // Check for specific database errors
            if (innerException?.Message.Contains("UNIQUE constraint", StringComparison.OrdinalIgnoreCase) == true)
            {
                return (
                    StatusCodes.Status409Conflict,
                    "DUPLICATE_ENTRY",
                    "A resource with the same key already exists"
                );
            }

            if (innerException?.Message.Contains("FOREIGN KEY constraint", StringComparison.OrdinalIgnoreCase) == true)
            {
                return (
                    StatusCodes.Status409Conflict,
                    "REFERENCE_CONSTRAINT",
                    "The operation would violate a reference constraint"
                );
            }

            if (innerException?.Message.Contains("cannot insert NULL", StringComparison.OrdinalIgnoreCase) == true)
            {
                return (
                    StatusCodes.Status400BadRequest,
                    "NULL_VALUE_ERROR",
                    "A required field contains a null value"
                );
            }

            return (
                StatusCodes.Status500InternalServerError,
                "DATABASE_ERROR",
                "A database error occurred"
            );
        }

        private string FormatValidationErrors(ValidationException exception)
        {
            if (exception.Errors?.Any() == true)
            {
                var errors = exception.Errors
                    .Select(e => $"{e.PropertyName}: {e.ErrorMessage}")
                    .Take(5); // Limit to first 5 errors

                return $"Validation failed: {string.Join("; ", errors)}";
            }

            return "Validation failed";
        }

        private int DetermineStatusCode(ServiceExceptionBase exception)
        {
            return exception.Severity switch
            {
                ErrorSeverity.Critical => StatusCodes.Status500InternalServerError,
                ErrorSeverity.Error => StatusCodes.Status400BadRequest,
                ErrorSeverity.Warning => StatusCodes.Status422UnprocessableEntity,
                _ => StatusCodes.Status500InternalServerError
            };
        }

        private string SanitizeMessage(string message)
        {
            if (string.IsNullOrWhiteSpace(message))
                return "An error occurred";

            // Remove sensitive patterns
            var sanitized = message;

            // Remove file paths
            sanitized = System.Text.RegularExpressions.Regex.Replace(
                sanitized,
                @"[a-zA-Z]:[\\\/](?:[^\\\/\r\n]+[\\\/])*[^\\\/\r\n]+",
                "[PATH]");

            // Remove potential secrets (API keys, passwords)
            sanitized = System.Text.RegularExpressions.Regex.Replace(
                sanitized,
                @"(api[_-]?key|password|secret|token)['\""=:\s]+[^\s'\""]+",
                "$1=[REDACTED]",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            // Remove email addresses
            sanitized = System.Text.RegularExpressions.Regex.Replace(
                sanitized,
                @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "[EMAIL]");

            // Remove IP addresses
            sanitized = System.Text.RegularExpressions.Regex.Replace(
                sanitized,
                @"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                "[IP]");

            // Truncate if too long
            if (sanitized.Length > 500)
            {
                sanitized = sanitized.Substring(0, 497) + "...";
            }

            return sanitized;
        }

        private Dictionary<string, object> FilterSensitiveData(System.Collections.IDictionary data)
        {
            if (data == null || data.Count == 0)
                return null;

            var filtered = new Dictionary<string, object>();
            var sensitiveKeys = new[] { "password", "secret", "key", "token", "credential" };

            foreach (var key in data.Keys)
            {
                var keyStr = key?.ToString() ?? "";
                
                if (sensitiveKeys.Any(sk => keyStr.Contains(sk, StringComparison.OrdinalIgnoreCase)))
                {
                    filtered[keyStr] = "[REDACTED]";
                }
                else
                {
                    var value = data[key];
                    filtered[keyStr] = value?.ToString() ?? "null";
                }
            }

            return filtered;
        }

        private string GenerateCorrelationId()
        {
            return $"ERR-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid():N}".Substring(0, 32);
        }

        private void LogError(Exception exception, string correlationId, HttpContext context)
        {
            var logLevel = DetermineLogLevel(exception);
            var requestPath = context.Request.Path;
            var requestMethod = context.Request.Method;
            var userId = context.User?.Identity?.Name ?? "Anonymous";

            using (_logger.BeginScope(new Dictionary<string, object>
            {
                ["CorrelationId"] = correlationId,
                ["RequestPath"] = requestPath,
                ["RequestMethod"] = requestMethod,
                ["UserId"] = userId,
                ["ExceptionType"] = exception.GetType().Name,
                ["MachineName"] = Environment.MachineName
            }))
            {
                _logger.Log(
                    logLevel,
                    exception,
                    "Unhandled exception occurred. CorrelationId: {CorrelationId}",
                    correlationId);
            }
        }

        private LogLevel DetermineLogLevel(Exception exception)
        {
            return exception switch
            {
                ServiceExceptionBase seb => seb.Severity switch
                {
                    ErrorSeverity.Critical => LogLevel.Critical,
                    ErrorSeverity.Error => LogLevel.Error,
                    ErrorSeverity.Warning => LogLevel.Warning,
                    _ => LogLevel.Error
                },
                
                DbUpdateConcurrencyException _ => LogLevel.Warning,
                ValidationException _ => LogLevel.Information,
                ArgumentException _ => LogLevel.Information,
                KeyNotFoundException _ => LogLevel.Information,
                FileNotFoundException _ => LogLevel.Information,
                UnauthorizedAccessException _ => LogLevel.Warning,
                SecurityException _ => LogLevel.Warning,
                OutOfMemoryException _ => LogLevel.Critical,
                _ => LogLevel.Error
            };
        }

        // Nested classes
        private class ErrorResponseFactory
        {
            public ErrorResponse Create(int statusCode, string errorCode, string message, string correlationId)
            {
                return new ErrorResponse
                {
                    StatusCode = statusCode,
                    ErrorCode = errorCode,
                    Message = message,
                    CorrelationId = correlationId,
                    Timestamp = DateTime.UtcNow,
                    Path = null // Will be set by the middleware if needed
                };
            }
        }

        private class ErrorMetricsCollector
        {
            private readonly Dictionary<string, ErrorMetric> _metrics = new();
            private readonly object _lock = new();

            public void RecordError(string exceptionType, int statusCode)
            {
                lock (_lock)
                {
                    var key = $"{exceptionType}:{statusCode}";
                    
                    if (_metrics.TryGetValue(key, out var metric))
                    {
                        metric.Count++;
                        metric.LastOccurrence = DateTime.UtcNow;
                    }
                    else
                    {
                        _metrics[key] = new ErrorMetric
                        {
                            ExceptionType = exceptionType,
                            StatusCode = statusCode,
                            Count = 1,
                            FirstOccurrence = DateTime.UtcNow,
                            LastOccurrence = DateTime.UtcNow
                        };
                    }
                }
            }

            public Dictionary<string, ErrorMetric> GetMetrics()
            {
                lock (_lock)
                {
                    return new Dictionary<string, ErrorMetric>(_metrics);
                }
            }
        }

        private class ErrorMetric
        {
            public string ExceptionType { get; set; }
            public int StatusCode { get; set; }
            public long Count { get; set; }
            public DateTime FirstOccurrence { get; set; }
            public DateTime LastOccurrence { get; set; }
        }
    }

    // Response classes
    public class ErrorResponse
    {
        public int StatusCode { get; set; }
        public string ErrorCode { get; set; }
        public string Message { get; set; }
        public string CorrelationId { get; set; }
        public DateTime Timestamp { get; set; }
        public string Path { get; set; }
        public ErrorDetails Details { get; set; }
    }

    public class ErrorDetails
    {
        public string ExceptionType { get; set; }
        public string InnerError { get; set; }
        public string StackTrace { get; set; }
        public Dictionary<string, object> Data { get; set; }
    }

    // Custom exceptions
    public abstract class ServiceExceptionBase : Exception
    {
        public string ErrorCode { get; set; }
        public ErrorSeverity Severity { get; set; }
        public Dictionary<string, object> Context { get; set; }

        protected ServiceExceptionBase(string message, string errorCode = null, ErrorSeverity severity = ErrorSeverity.Error)
            : base(message)
        {
            ErrorCode = errorCode;
            Severity = severity;
            Context = new Dictionary<string, object>();
        }

        protected ServiceExceptionBase(string message, Exception innerException, string errorCode = null, ErrorSeverity severity = ErrorSeverity.Error)
            : base(message, innerException)
        {
            ErrorCode = errorCode;
            Severity = severity;
            Context = new Dictionary<string, object>();
        }
    }

    public enum ErrorSeverity
    {
        Warning,
        Error,
        Critical
    }

    public class AnalysisServiceException : ServiceExceptionBase
    {
        public Guid? AnalysisId { get; set; }

        public AnalysisServiceException(string message, Guid? analysisId = null, string errorCode = null)
            : base(message, errorCode)
        {
            AnalysisId = analysisId;
            if (analysisId.HasValue)
            {
                Context["AnalysisId"] = analysisId.Value;
            }
        }

        public AnalysisServiceException(string message, Exception innerException, Guid? analysisId = null)
            : base(message, innerException)
        {
            AnalysisId = analysisId;
            if (analysisId.HasValue)
            {
                Context["AnalysisId"] = analysisId.Value;
            }
        }
    }

    public class ParserServiceException : ServiceExceptionBase
    {
        public Guid? ParserId { get; set; }

        public ParserServiceException(string message, Guid? parserId = null, string errorCode = null)
            : base(message, errorCode)
        {
            ParserId = parserId;
            if (parserId.HasValue)
            {
                Context["ParserId"] = parserId.Value;
            }
        }

        public ParserServiceException(string message, Exception innerException, Guid? parserId = null)
            : base(message, innerException)
        {
            ParserId = parserId;
            if (parserId.HasValue)
            {
                Context["ParserId"] = parserId.Value;
            }
        }
    }

    public class AIServiceException : ServiceExceptionBase
    {
        public string Model { get; set; }
        public int? TokensUsed { get; set; }

        public AIServiceException(string message, string model = null, int? tokensUsed = null)
            : base(message, "AI_SERVICE_ERROR")
        {
            Model = model;
            TokensUsed = tokensUsed;
            if (!string.IsNullOrEmpty(model))
            {
                Context["Model"] = model;
            }
            if (tokensUsed.HasValue)
            {
                Context["TokensUsed"] = tokensUsed.Value;
            }
        }

        public AIServiceException(string message, Exception innerException)
            : base(message, innerException, "AI_SERVICE_ERROR")
        {
        }
    }

    public class IOCExtractionException : ServiceExceptionBase
    {
        public string ContentType { get; set; }
        public int? ContentLength { get; set; }

        public IOCExtractionException(string message, string contentType = null)
            : base(message, "IOC_EXTRACTION_ERROR")
        {
            ContentType = contentType;
            if (!string.IsNullOrEmpty(contentType))
            {
                Context["ContentType"] = contentType;
            }
        }
    }

    public class MITREMappingException : ServiceExceptionBase
    {
        public string TechniqueId { get; set; }

        public MITREMappingException(string message, string techniqueId = null)
            : base(message, "MITRE_MAPPING_ERROR")
        {
            TechniqueId = techniqueId;
            if (!string.IsNullOrEmpty(techniqueId))
            {
                Context["TechniqueId"] = techniqueId;
            }
        }
    }

    public class PluginLoadException : ServiceExceptionBase
    {
        public Guid? PluginId { get; set; }

        public PluginLoadException(string message, Guid? pluginId = null)
            : base(message, "PLUGIN_LOAD_ERROR", ErrorSeverity.Critical)
        {
            PluginId = pluginId;
            if (pluginId.HasValue)
            {
                Context["PluginId"] = pluginId.Value;
            }
        }

        public PluginLoadException(string message, Exception innerException, Guid? pluginId = null)
            : base(message, innerException, "PLUGIN_LOAD_ERROR", ErrorSeverity.Critical)
        {
            PluginId = pluginId;
            if (pluginId.HasValue)
            {
                Context["PluginId"] = pluginId.Value;
            }
        }
    }

    public class RateLimitExceededException : ServiceExceptionBase
    {
        public int? RetryAfterSeconds { get; set; }

        public RateLimitExceededException(string message, int? retryAfterSeconds = null)
            : base(message, "RATE_LIMIT_EXCEEDED", ErrorSeverity.Warning)
        {
            RetryAfterSeconds = retryAfterSeconds;
            if (retryAfterSeconds.HasValue)
            {
                Context["RetryAfter"] = retryAfterSeconds.Value;
            }
        }
    }

    // Extension for middleware registration
    public static class ErrorHandlingMiddlewareExtensions
    {
        public static IApplicationBuilder UseErrorHandling(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ErrorHandlingMiddleware>();
        }
    }
}