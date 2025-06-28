using System.Net;
using System.Text.Json;

namespace SecuNik.LogX.Api.Middleware
{
    public class ErrorHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ErrorHandlingMiddleware> _logger;
        private readonly IWebHostEnvironment _environment;
        
        public ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger, IWebHostEnvironment environment)
        {
            _next = next;
            _logger = logger;
            _environment = environment;
        }
        
        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occurred");
                await HandleExceptionAsync(context, ex);
            }
        }
        
        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            context.Response.ContentType = "application/json";
            
            var response = new ErrorResponse();
            
            switch (exception)
            {
                case ArgumentException argEx:
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    response.Message = "Invalid argument provided";
                    response.Detail = new ErrorDetail
                    {
                        Message = argEx.Message,
                        ErrorCode = "INVALID_ARGUMENT",
                        Details = new Dictionary<string, object>
                        {
                            ["parameter"] = argEx.ParamName ?? "unknown"
                        }
                    };
                    break;
                    
                case FileNotFoundException fileEx:
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    response.Message = "File not found";
                    response.Detail = new ErrorDetail
                    {
                        Message = fileEx.Message,
                        ErrorCode = "FILE_NOT_FOUND",
                        Details = new Dictionary<string, object>
                        {
                            ["filename"] = fileEx.FileName ?? "unknown"
                        }
                    };
                    break;
                    
                case DirectoryNotFoundException dirEx:
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    response.Message = "Directory not found";
                    response.Detail = new ErrorDetail
                    {
                        Message = dirEx.Message,
                        ErrorCode = "DIRECTORY_NOT_FOUND"
                    };
                    break;
                    
                case UnauthorizedAccessException:
                    response.StatusCode = (int)HttpStatusCode.Forbidden;
                    response.Message = "Access denied";
                    response.Detail = new ErrorDetail
                    {
                        Message = "Insufficient permissions to perform this operation",
                        ErrorCode = "ACCESS_DENIED"
                    };
                    break;
                    
                case InvalidOperationException invalidOpEx:
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    response.Message = "Invalid operation";
                    response.Detail = new ErrorDetail
                    {
                        Message = invalidOpEx.Message,
                        ErrorCode = "INVALID_OPERATION"
                    };
                    break;
                    
                case TimeoutException timeoutEx:
                    response.StatusCode = (int)HttpStatusCode.RequestTimeout;
                    response.Message = "Operation timed out";
                    response.Detail = new ErrorDetail
                    {
                        Message = timeoutEx.Message,
                        ErrorCode = "TIMEOUT"
                    };
                    break;
                    
                case NotSupportedException notSupportedEx:
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    response.Message = "Operation not supported";
                    response.Detail = new ErrorDetail
                    {
                        Message = notSupportedEx.Message,
                        ErrorCode = "NOT_SUPPORTED"
                    };
                    break;
                    
                case OutOfMemoryException:
                    response.StatusCode = (int)HttpStatusCode.InsufficientStorage;
                    response.Message = "Insufficient memory";
                    response.Detail = new ErrorDetail
                    {
                        Message = "The operation requires more memory than is available",
                        ErrorCode = "OUT_OF_MEMORY"
                    };
                    break;
                    
                case IOException ioEx:
                    response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    response.Message = "I/O error occurred";
                    response.Detail = new ErrorDetail
                    {
                        Message = ioEx.Message,
                        ErrorCode = "IO_ERROR"
                    };
                    break;
                    
                default:
                    response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    response.Message = "An internal server error occurred";
                    response.Detail = new ErrorDetail
                    {
                        Message = _environment.IsDevelopment() ? exception.Message : "An unexpected error occurred",
                        ErrorCode = "INTERNAL_ERROR"
                    };
                    
                    if (_environment.IsDevelopment())
                    {
                        response.Detail.Details = new Dictionary<string, object>
                        {
                            ["exception_type"] = exception.GetType().Name,
                            ["stack_trace"] = exception.StackTrace ?? "No stack trace available"
                        };
                    }
                    break;
            }
            
            context.Response.StatusCode = response.StatusCode;
            
            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = _environment.IsDevelopment()
            };
            
            var jsonResponse = JsonSerializer.Serialize(response, jsonOptions);
            await context.Response.WriteAsync(jsonResponse);
        }
    }
    
    public class ErrorResponse
    {
        public bool Success { get; set; } = false;
        public int StatusCode { get; set; }
        public string Message { get; set; } = string.Empty;
        public ErrorDetail? Detail { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string RequestId { get; set; } = Guid.NewGuid().ToString();
    }
    
    public class ErrorDetail
    {
        public string Message { get; set; } = string.Empty;
        public string ErrorCode { get; set; } = string.Empty;
        public Dictionary<string, object> Details { get; set; } = new();
    }
}