using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Serilog.Context;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SecuNikLogX.API.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;
        private readonly IConfiguration _configuration;
        private readonly HashSet<string> _sensitiveHeaders;
        private readonly HashSet<string> _sensitiveFields;
        private readonly List<Regex> _sensitivePatterns;
        private readonly int _maxBodyLength;
        private readonly bool _includeHeaders;
        private readonly LogLevel _logLevel;

        public RequestLoggingMiddleware(
            RequestDelegate next,
            ILogger<RequestLoggingMiddleware> logger,
            IConfiguration configuration)
        {
            _next = next;
            _logger = logger;
            _configuration = configuration;

            // Load configuration
            _maxBodyLength = _configuration.GetValue<int>("RequestLogging:MaxBodyLength", 4096);
            _includeHeaders = _configuration.GetValue<bool>("RequestLogging:IncludeHeaders", true);
            _logLevel = Enum.Parse<LogLevel>(_configuration.GetValue<string>("RequestLogging:LogLevel", "Information"));

            // Sensitive headers to redact
            _sensitiveHeaders = _configuration.GetSection("RequestLogging:SensitiveHeaders")
                .Get<HashSet<string>>() ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "Authorization",
                    "X-API-Key",
                    "Cookie",
                    "Set-Cookie"
                };

            // Sensitive field names to redact in request/response bodies
            _sensitiveFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "password",
                "apikey",
                "api_key",
                "secret",
                "token",
                "accesstoken",
                "access_token",
                "refreshtoken",
                "refresh_token",
                "private_key",
                "privatekey",
                "creditcard",
                "credit_card",
                "ssn",
                "socialsecuritynumber"
            };

            // Regex patterns for sensitive data
            _sensitivePatterns = new List<Regex>
            {
                new Regex(@"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b", RegexOptions.Compiled), // Credit cards
                new Regex(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled), // SSN
                new Regex(@"Bearer\s+[A-Za-z0-9\-_]+\.?[A-Za-z0-9\-_]*\.?[A-Za-z0-9\-_]*", RegexOptions.Compiled), // Bearer tokens
                new Regex(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", RegexOptions.Compiled) // Email addresses (optional redaction)
            };
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Generate correlation ID
            var correlationId = Guid.NewGuid().ToString("N");
            context.Items["CorrelationId"] = correlationId;

            // Add correlation ID to response headers
            context.Response.OnStarting(() =>
            {
                context.Response.Headers["X-Correlation-Id"] = correlationId;
                return Task.CompletedTask;
            });

            // Use Serilog context to enrich all logs with correlation ID
            using (LogContext.PushProperty("CorrelationId", correlationId))
            {
                var stopwatch = Stopwatch.StartNew();
                var originalBodyStream = context.Response.Body;

                try
                {
                    // Log request
                    await LogRequestAsync(context, correlationId);

                    // Buffer response body for logging
                    using var responseBodyStream = new MemoryStream();
                    context.Response.Body = responseBodyStream;

                    // Process request
                    await _next(context);

                    // Log response
                    await LogResponseAsync(context, responseBodyStream, stopwatch.ElapsedMilliseconds, correlationId);

                    // Copy response to original stream
                    responseBodyStream.Seek(0, SeekOrigin.Begin);
                    await responseBodyStream.CopyToAsync(originalBodyStream);
                }
                catch (Exception ex)
                {
                    stopwatch.Stop();
                    
                    _logger.LogError(ex, 
                        "Request {Method} {Path} failed after {ElapsedMs}ms. CorrelationId: {CorrelationId}",
                        context.Request.Method,
                        context.Request.Path,
                        stopwatch.ElapsedMilliseconds,
                        correlationId);

                    throw;
                }
                finally
                {
                    context.Response.Body = originalBodyStream;
                }
            }
        }

        private async Task LogRequestAsync(HttpContext context, string correlationId)
        {
            if (!ShouldLog(_logLevel))
                return;

            var request = context.Request;
            var logMessage = new StringBuilder();

            logMessage.AppendLine($"HTTP Request Information:");
            logMessage.AppendLine($"CorrelationId: {correlationId}");
            logMessage.AppendLine($"Method: {request.Method}");
            logMessage.AppendLine($"Path: {request.Path}");
            logMessage.AppendLine($"QueryString: {request.QueryString}");
            logMessage.AppendLine($"ContentType: {request.ContentType}");
            logMessage.AppendLine($"ContentLength: {request.ContentLength}");
            logMessage.AppendLine($"UserAgent: {request.Headers["User-Agent"]}");
            logMessage.AppendLine($"RemoteIP: {context.Connection.RemoteIpAddress}");

            if (_includeHeaders)
            {
                logMessage.AppendLine("Headers:");
                foreach (var header in request.Headers)
                {
                    var headerValue = _sensitiveHeaders.Contains(header.Key)
                        ? "[REDACTED]"
                        : string.Join(", ", header.Value);
                    
                    logMessage.AppendLine($"  {header.Key}: {headerValue}");
                }
            }

            // Log request body if present and not too large
            if (request.ContentLength > 0 && request.ContentLength < _maxBodyLength)
            {
                request.EnableBuffering();
                
                using var reader = new StreamReader(
                    request.Body,
                    encoding: Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: false,
                    leaveOpen: true);
                
                var body = await reader.ReadToEndAsync();
                request.Body.Position = 0;

                if (!string.IsNullOrEmpty(body))
                {
                    var redactedBody = RedactSensitiveData(body);
                    logMessage.AppendLine($"Body: {redactedBody}");
                }
            }
            else if (request.ContentLength > _maxBodyLength)
            {
                logMessage.AppendLine($"Body: [TRUNCATED - Size: {request.ContentLength} bytes]");
            }

            _logger.Log(_logLevel, logMessage.ToString());
        }

        private async Task LogResponseAsync(
            HttpContext context, 
            MemoryStream responseBodyStream, 
            long elapsedMs, 
            string correlationId)
        {
            if (!ShouldLog(_logLevel))
                return;

            var response = context.Response;
            var logMessage = new StringBuilder();

            logMessage.AppendLine($"HTTP Response Information:");
            logMessage.AppendLine($"CorrelationId: {correlationId}");
            logMessage.AppendLine($"StatusCode: {response.StatusCode}");
            logMessage.AppendLine($"ContentType: {response.ContentType}");
            logMessage.AppendLine($"ContentLength: {response.ContentLength ?? responseBodyStream.Length}");
            logMessage.AppendLine($"ElapsedTime: {elapsedMs}ms");

            if (_includeHeaders)
            {
                logMessage.AppendLine("Headers:");
                foreach (var header in response.Headers)
                {
                    var headerValue = _sensitiveHeaders.Contains(header.Key)
                        ? "[REDACTED]"
                        : string.Join(", ", header.Value);
                    
                    logMessage.AppendLine($"  {header.Key}: {headerValue}");
                }
            }

            // Log response body if not too large
            if (responseBodyStream.Length > 0 && responseBodyStream.Length < _maxBodyLength)
            {
                responseBodyStream.Seek(0, SeekOrigin.Begin);
                using var reader = new StreamReader(responseBodyStream, leaveOpen: true);
                var body = await reader.ReadToEndAsync();
                responseBodyStream.Seek(0, SeekOrigin.Begin);

                if (!string.IsNullOrEmpty(body))
                {
                    var redactedBody = RedactSensitiveData(body);
                    logMessage.AppendLine($"Body: {redactedBody}");
                }
            }
            else if (responseBodyStream.Length > _maxBodyLength)
            {
                logMessage.AppendLine($"Body: [TRUNCATED - Size: {responseBodyStream.Length} bytes]");
            }

            // Log with appropriate level based on status code
            var logLevel = response.StatusCode >= 400 ? LogLevel.Warning : _logLevel;
            _logger.Log(logLevel, logMessage.ToString());

            // Log performance warning if request took too long
            var performanceThreshold = _configuration.GetValue<long>("RequestLogging:PerformanceThresholdMs", 1000);
            if (elapsedMs > performanceThreshold)
            {
                _logger.LogWarning(
                    "Slow request detected: {Method} {Path} took {ElapsedMs}ms. CorrelationId: {CorrelationId}",
                    context.Request.Method,
                    context.Request.Path,
                    elapsedMs,
                    correlationId);
            }
        }

        private string RedactSensitiveData(string content)
        {
            if (string.IsNullOrEmpty(content))
                return content;

            // Apply regex patterns
            foreach (var pattern in _sensitivePatterns)
            {
                content = pattern.Replace(content, "[REDACTED]");
            }

            // Redact JSON fields
            if (IsJson(content))
            {
                foreach (var field in _sensitiveFields)
                {
                    var jsonPattern = new Regex(
                        $@"""{field}""\s*:\s*""[^""]*""",
                        RegexOptions.IgnoreCase);
                    content = jsonPattern.Replace(content, $"\"{field}\":\"[REDACTED]\"");
                }
            }

            // Redact URL-encoded form fields
            if (IsFormUrlEncoded(content))
            {
                foreach (var field in _sensitiveFields)
                {
                    var formPattern = new Regex(
                        $@"{field}=[^&]*",
                        RegexOptions.IgnoreCase);
                    content = formPattern.Replace(content, $"{field}=[REDACTED]");
                }
            }

            return content;
        }

        private bool IsJson(string content)
        {
            content = content.Trim();
            return (content.StartsWith("{") && content.EndsWith("}")) ||
                   (content.StartsWith("[") && content.EndsWith("]"));
        }

        private bool IsFormUrlEncoded(string content)
        {
            return content.Contains("=") && content.Contains("&");
        }

        private bool ShouldLog(LogLevel logLevel)
        {
            return _logger.IsEnabled(logLevel);
        }
    }

    public static class RequestLoggingMiddlewareExtensions
    {
        public static IApplicationBuilder UseRequestLogging(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<RequestLoggingMiddleware>();
        }
    }
}