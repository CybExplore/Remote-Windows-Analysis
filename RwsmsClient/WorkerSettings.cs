using System.ComponentModel.DataAnnotations;

namespace RwsmsClient;

public class WorkerSettings
{
    [Required]
    public string ApiBaseUrl { get; set; } = string.Empty;
    
    [Required]
    public string LogFilePath { get; set; } = string.Empty;
    
    [Range(1, 1000)]
    public int BatchSize { get; set; } = 100;
    
    [Range(1, 3600)]
    public int PollIntervalSeconds { get; set; } = 5;
    
    [Range(1, 3600)]
    public int RetryDelaySeconds { get; set; } = 60;
    
    public string UserEmail { get; set; } = string.Empty;
    
    public string FullName { get; set; } = "Default User";
    
    public string FrontendUrl { get; set; } = string.Empty;
    
    public string[] LogNames { get; set; } = ["System", "Application", "Security"];
}