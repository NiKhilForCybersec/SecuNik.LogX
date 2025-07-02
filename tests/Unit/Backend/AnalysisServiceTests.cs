using Xunit;
using Moq;
using SecuNikLogX.API.Services;
using SecuNikLogX.API.Models;
using SecuNikLogX.API.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;

namespace SecuNikLogX.Tests.Unit.Backend
{
    public class AnalysisServiceTests : IDisposable
    {
        private readonly ApplicationDbContext _context;
        private readonly Mock<ILogger<AnalysisService>> _loggerMock;
        private readonly Mock<IOCExtractor> _iocExtractorMock;
        private readonly Mock<MITREMapper> _mitreMapperMock;
        private readonly Mock<AIService> _aiServiceMock;
        private readonly AnalysisService _analysisService;

        public AnalysisServiceTests()
        {
            // Setup in-memory database
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;
            _context = new ApplicationDbContext(options);
            
            // Setup mocks
            _loggerMock = new Mock<ILogger<AnalysisService>>();
            _iocExtractorMock = new Mock<IOCExtractor>();
            _mitreMapperMock = new Mock<MITREMapper>();
            _aiServiceMock = new Mock<AIService>();
            
            // Create service
            _analysisService = new AnalysisService(
                _context,
                _loggerMock.Object,
                _iocExtractorMock.Object,
                _mitreMapperMock.Object,
                _aiServiceMock.Object
            );
        }

        [Fact]
        public async Task CreateAnalysisAsync_ValidInput_ReturnsNewAnalysis()
        {
            // Arrange
            var request = new CreateAnalysisRequest
            {
                FileName = "test.log",
                FileHash = "abc123",
                FileSize = 1024,
                AnalysisType = "standard"
            };

            // Act
            var result = await _analysisService.CreateAnalysisAsync(request);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("test.log", result.FileName);
            Assert.Equal("pending", result.Status);
            Assert.True(await _context.Analyses.AnyAsync(a => a.Id == result.Id));
        }

        [Fact]
        public async Task StartAnalysisAsync_ExistingAnalysis_UpdatesStatusAndStartsProcessing()
        {
            // Arrange
            var analysis = new Analysis
            {
                Id = Guid.NewGuid(),
                FileName = "test.log",
                Status = "pending",
                CreatedAt = DateTime.UtcNow
            };
            _context.Analyses.Add(analysis);
            await _context.SaveChangesAsync();

            _iocExtractorMock
                .Setup(x => x.ExtractIOCsAsync(It.IsAny<string>(), It.IsAny<IOCExtractionOptions>(), default))
                .ReturnsAsync(new List<ExtractedIOC>());

            // Act
            await _analysisService.StartAnalysisAsync(analysis.Id);

            // Assert
            var updated = await _context.Analyses.FindAsync(analysis.Id);
            Assert.Equal("processing", updated.Status);
        }

        [Fact]
        public async Task GetAnalysesByDateRangeAsync_ValidRange_ReturnsFilteredResults()
        {
            // Arrange
            var now = DateTime.UtcNow;
            var analyses = new List<Analysis>
            {
                new Analysis { Id = Guid.NewGuid(), CreatedAt = now.AddDays(-5), FileName = "old.log" },
                new Analysis { Id = Guid.NewGuid(), CreatedAt = now.AddDays(-1), FileName = "recent.log" },
                new Analysis { Id = Guid.NewGuid(), CreatedAt = now.AddDays(-10), FileName = "older.log" }
            };
            _context.Analyses.AddRange(analyses);
            await _context.SaveChangesAsync();

            // Act
            var result = await _analysisService.GetAnalysesByDateRangeAsync(
                now.AddDays(-7), 
                now
            );

            // Assert
            Assert.Equal(2, result.Count());
            Assert.Contains(result, a => a.FileName == "recent.log");
        }

        [Theory]
        [InlineData("critical", 3)]
        [InlineData("high", 2)]
        [InlineData("medium", 1)]
        [InlineData("low", 0)]
        public async Task CalculateThreatLevel_BasedOnIOCCount_ReturnsCorrectLevel(string expectedLevel, int iocCount)
        {
            // This would test the threat level calculation logic
            // Implementation depends on actual business logic
            Assert.Equal(expectedLevel, AnalysisService.CalculateThreatLevel(iocCount, 0));
        }

        public void Dispose()
        {
            _context?.Dispose();
        }
    }
}