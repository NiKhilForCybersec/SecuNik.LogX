using SecuNik.LogX.Core.Interfaces;
using SecuNik.LogX.Core.DTOs;
using System.Text.Json;

namespace SecuNik.LogX.Api.Services.Analysis
{
    public class TimelineBuilder
    {
        private readonly ILogger<TimelineBuilder> _logger;

        public TimelineBuilder(ILogger<TimelineBuilder> logger)
        {
            _logger = logger;
        }

        public async Task<List<TimelineEventDto>> BuildTimelineAsync(
            List<LogEvent> events, 
            List<RuleMatchResult> ruleMatches,
            CancellationToken cancellationToken = default)
        {
            var timeline = new List<TimelineEventDto>();
            
            try
            {
                // Add events to timeline
                foreach (var evt in events)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    var timelineEvent = new TimelineEventDto
                    {
                        Id = Guid.NewGuid(),
                        Timestamp = evt.Timestamp,
                        EventType = "log_event",
                        Title = evt.Message,
                        Description = evt.Message,
                        Severity = MapLogLevelToSeverity(evt.Level),
                        Source = evt.Source,
                        Category = "log",
                        LineNumber = evt.LineNumber,
                        RawData = evt.RawData,
                        Details = new Dictionary<string, object>(evt.Fields)
                    };
                    
                    timeline.Add(timelineEvent);
                }
                
                // Add rule matches to timeline
                foreach (var match in ruleMatches)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    foreach (var detail in match.Matches)
                    {
                        var timelineEvent = new TimelineEventDto
                        {
                            Id = Guid.NewGuid(),
                            Timestamp = detail.Timestamp ?? DateTime.UtcNow,
                            EventType = "rule_match",
                            Title = $"Rule Match: {match.RuleName}",
                            Description = detail.MatchedContent,
                            Severity = match.Severity.ToString().ToLower(),
                            Source = "rule_engine",
                            Category = "detection",
                            LineNumber = detail.LineNumber,
                            RawData = detail.MatchedContent,
                            Details = new Dictionary<string, object>
                            {
                                ["rule_id"] = match.RuleId,
                                ["rule_name"] = match.RuleName,
                                ["rule_type"] = match.RuleType.ToString(),
                                ["confidence"] = match.Confidence,
                                ["context"] = detail.Context ?? string.Empty
                            },
                            MitreAttackIds = match.MitreAttackIds,
                            IsAnomalous = true,
                            Confidence = match.Confidence
                        };
                        
                        timeline.Add(timelineEvent);
                    }
                }
                
                // Sort timeline by timestamp
                timeline = timeline.OrderBy(e => e.Timestamp).ToList();
                
                _logger.LogInformation("Built timeline with {EventCount} events", timeline.Count);
                return timeline;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error building timeline");
                throw;
            }
        }
        
        private string MapLogLevelToSeverity(string logLevel)
        {
            return logLevel.ToUpperInvariant() switch
            {
                "CRITICAL" => "critical",
                "FATAL" => "critical",
                "ERROR" => "high",
                "WARNING" => "medium",
                "WARN" => "medium",
                "INFO" => "low",
                "DEBUG" => "info",
                "TRACE" => "info",
                _ => "info"
            };
        }
        
        public TimelineStatisticsDto CalculateStatistics(List<TimelineEventDto> timeline)
        {
            if (timeline == null || timeline.Count == 0)
            {
                return new TimelineStatisticsDto();
            }
            
            var stats = new TimelineStatisticsDto
            {
                TotalEvents = timeline.Count,
                FirstEvent = timeline.Min(e => e.Timestamp),
                LastEvent = timeline.Max(e => e.Timestamp)
            };
            
            stats.TimeRange = stats.LastEvent - stats.FirstEvent;
            
            // Events by type
            stats.EventsByType = timeline
                .GroupBy(e => e.EventType)
                .ToDictionary(g => g.Key, g => g.Count());
                
            // Events by severity
            stats.EventsBySeverity = timeline
                .GroupBy(e => e.Severity)
                .ToDictionary(g => g.Key, g => g.Count());
                
            // Events by source
            stats.EventsBySource = timeline
                .Where(e => !string.IsNullOrEmpty(e.Source))
                .GroupBy(e => e.Source)
                .ToDictionary(g => g.Key, g => g.Count());
                
            // Events by category
            stats.EventsByCategory = timeline
                .Where(e => !string.IsNullOrEmpty(e.Category))
                .GroupBy(e => e.Category)
                .ToDictionary(g => g.Key, g => g.Count());
                
            // Events by hour
            stats.EventsByHour = timeline
                .GroupBy(e => new DateTime(
                    e.Timestamp.Year,
                    e.Timestamp.Month,
                    e.Timestamp.Day,
                    e.Timestamp.Hour,
                    0, 0))
                .ToDictionary(g => g.Key, g => g.Count());
                
            // Top tags
            stats.TopTags = timeline
                .SelectMany(e => e.Tags)
                .GroupBy(t => t)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .Select(g => g.Key)
                .ToList();
                
            // Anomalous events
            stats.AnomalousEvents = timeline.Count(e => e.IsAnomalous);
            
            return stats;
        }
    }
}