namespace SecuNik.LogX.Core.DTOs
{
    public class MitreAttackDto
    {
        public List<TechniqueDto> Techniques { get; set; } = new();
        
        public List<TacticDto> Tactics { get; set; } = new();
        
        public List<string> KillChainPhases { get; set; } = new();
        
        public Dictionary<string, int> TechniqueFrequency { get; set; } = new();
        
        public Dictionary<string, int> TacticFrequency { get; set; } = new();
        
        public MitreStatisticsDto Statistics { get; set; } = new();
    }
    
    public class TechniqueDto
    {
        public string TechniqueId { get; set; } = string.Empty;
        
        public string TechniqueName { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public List<string> Tactics { get; set; } = new();
        
        public List<string> Platforms { get; set; } = new();
        
        public List<string> DataSources { get; set; } = new();
        
        public List<SubTechniqueDto> SubTechniques { get; set; } = new();
        
        public double Confidence { get; set; } = 1.0;
        
        public int MatchCount { get; set; }
        
        public List<string> Evidence { get; set; } = new();
        
        public Dictionary<string, object> Metadata { get; set; } = new();
    }
    
    public class SubTechniqueDto
    {
        public string SubTechniqueId { get; set; } = string.Empty;
        
        public string SubTechniqueName { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public double Confidence { get; set; } = 1.0;
        
        public int MatchCount { get; set; }
        
        public List<string> Evidence { get; set; } = new();
    }
    
    public class TacticDto
    {
        public string TacticId { get; set; } = string.Empty;
        
        public string TacticName { get; set; } = string.Empty;
        
        public string Description { get; set; } = string.Empty;
        
        public List<string> TechniqueIds { get; set; } = new();
        
        public int TechniqueCount { get; set; }
        
        public double Coverage { get; set; } // Percentage of techniques in this tactic that were detected
    }
    
    public class MitreStatisticsDto
    {
        public int TotalTechniques { get; set; }
        
        public int TotalTactics { get; set; }
        
        public int TotalSubTechniques { get; set; }
        
        public Dictionary<string, int> TechniquesByTactic { get; set; } = new();
        
        public Dictionary<string, double> ConfidenceByTactic { get; set; } = new();
        
        public List<string> MostCommonTechniques { get; set; } = new();
        
        public List<string> HighConfidenceTechniques { get; set; } = new();
        
        public double OverallThreatScore { get; set; }
    }
    
    public class MitreMapperResultDto
    {
        public string RuleId { get; set; } = string.Empty;
        
        public string RuleName { get; set; } = string.Empty;
        
        public List<string> MappedTechniques { get; set; } = new();
        
        public List<string> MappedTactics { get; set; } = new();
        
        public double MappingConfidence { get; set; } = 1.0;
        
        public string MappingSource { get; set; } = string.Empty; // rule_metadata, content_analysis, ml_prediction
        
        public Dictionary<string, object> MappingDetails { get; set; } = new();
    }
}