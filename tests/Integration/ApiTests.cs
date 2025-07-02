using Xunit;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net.Http;
using System.Threading.Tasks;
using System.Net;
using Newtonsoft.Json;
using SecuNikLogX.API;
using System.Text;
using System.IO;
using Microsoft.AspNetCore.SignalR.Client;

namespace SecuNikLogX.Tests.Integration
{
    public class ApiTests : IClassFixture<WebApplicationFactory<Program>>
    {
        private readonly WebApplicationFactory<Program> _factory;
        private readonly HttpClient _client;

        public ApiTests(WebApplicationFactory<Program> factory)
        {
            _factory = factory;
            _client = _factory.CreateClient();
        }

        [Fact]
        public async Task HealthCheck_ReturnsHealthy()
        {
            // Act
            var response = await _client.GetAsync("/health");

            // Assert
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            Assert.Contains("Healthy", content);
        }

        [Fact]
        public async Task GetAnalyses_ReturnsSuccessAndCorrectContentType()
        {
            // Act
            var response = await _client.GetAsync("/api/analysis");

            // Assert
            response.EnsureSuccessStatusCode();
            Assert.Equal("application/json; charset=utf-8", 
                response.Content.Headers.ContentType.ToString());
        }

        [Fact]
        public async Task CreateAnalysis_ValidInput_ReturnsCreatedAnalysis()
        {
            // Arrange
            var request = new
            {
                fileName = "integration-test.log",
                fileHash = "123abc",
                fileSize = 2048,
                analysisType = "standard"
            };
            var content = new StringContent(
                JsonConvert.SerializeObject(request),
                Encoding.UTF8,
                "application/json"
            );

            // Act
            var response = await _client.PostAsync("/api/analysis", content);

            // Assert
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var responseContent = await response.Content.ReadAsStringAsync();
            dynamic analysis = JsonConvert.DeserializeObject(responseContent);
            Assert.Equal("integration-test.log", (string)analysis.fileName);
        }

        [Fact]
        public async Task FileUpload_ValidFile_ReturnsSuccess()
        {
            // Arrange
            using var fileContent = new ByteArrayContent(Encoding.UTF8.GetBytes("test log content"));
            fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/plain");
            
            using var formData = new MultipartFormDataContent();
            formData.Add(fileContent, "file", "test-upload.log");

            // Act
            var response = await _client.PostAsync("/api/file/upload", formData);

            // Assert
            response.EnsureSuccessStatusCode();
            var responseContent = await response.Content.ReadAsStringAsync();
            Assert.Contains("fileId", responseContent);
        }

        [Fact]
        public async Task SignalRConnection_ConnectsSuccessfully()
        {
            // Arrange
            var connection = new HubConnectionBuilder()
                .WithUrl($"http://localhost/analysishub", options =>
                {
                    options.HttpMessageHandlerFactory = _ => _factory.Server.CreateHandler();
                })
                .Build();

            // Act & Assert
            await connection.StartAsync();
            Assert.Equal(HubConnectionState.Connected, connection.State);
            
            await connection.StopAsync();
        }

        [Fact]
        public async Task AnalysisWorkflow_EndToEnd_CompletesSuccessfully()
        {
            // Step 1: Upload file
            using var fileContent = new ByteArrayContent(Encoding.UTF8.GetBytes("malicious content"));
            fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/plain");
            
            using var formData = new MultipartFormDataContent();
            formData.Add(fileContent, "file", "malware.log");
            
            var uploadResponse = await _client.PostAsync("/api/file/upload", formData);
            uploadResponse.EnsureSuccessStatusCode();
            
            var uploadResult = JsonConvert.DeserializeObject<dynamic>(
                await uploadResponse.Content.ReadAsStringAsync()
            );
            string fileId = uploadResult.fileId;

            // Step 2: Create analysis
            var createRequest = new
            {
                fileName = "malware.log",
                fileHash = uploadResult.hash,
                fileSize = uploadResult.fileSize,
                analysisType = "standard"
            };
            
            var createContent = new StringContent(
                JsonConvert.SerializeObject(createRequest),
                Encoding.UTF8,
                "application/json"
            );
            
            var createResponse = await _client.PostAsync("/api/analysis", createContent);
            createResponse.EnsureSuccessStatusCode();
            
            var analysis = JsonConvert.DeserializeObject<dynamic>(
                await createResponse.Content.ReadAsStringAsync()
            );
            string analysisId = analysis.id;

            // Step 3: Start analysis
            var startResponse = await _client.PostAsync($"/api/analysis/{analysisId}/start", null);
            startResponse.EnsureSuccessStatusCode();

            // Step 4: Check status
            var statusResponse = await _client.GetAsync($"/api/analysis/{analysisId}");
            statusResponse.EnsureSuccessStatusCode();
            
            var status = JsonConvert.DeserializeObject<dynamic>(
                await statusResponse.Content.ReadAsStringAsync()
            );
            Assert.Equal("processing", (string)status.status);
        }

        [Theory]
        [InlineData("/api/analysis/00000000-0000-0000-0000-000000000000", HttpStatusCode.NotFound)]
        [InlineData("/api/analysis/invalid-guid", HttpStatusCode.BadRequest)]
        public async Task GetAnalysis_InvalidId_ReturnsExpectedError(string url, HttpStatusCode expectedStatus)
        {
            // Act
            var response = await _client.GetAsync(url);

            // Assert
            Assert.Equal(expectedStatus, response.StatusCode);
        }

        [Fact]
        public async Task RateLimiting_ExceedsLimit_Returns429()
        {
            // Make many requests quickly
            var tasks = new Task<HttpResponseMessage>[100];
            for (int i = 0; i < 100; i++)
            {
                tasks[i] = _client.GetAsync("/api/analysis");
            }

            var responses = await Task.WhenAll(tasks);
            
            // At least one should be rate limited
            Assert.Contains(responses, r => r.StatusCode == HttpStatusCode.TooManyRequests);
        }
    }
}