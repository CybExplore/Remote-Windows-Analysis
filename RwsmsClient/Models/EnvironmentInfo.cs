// EnvironmentInfo.cs
namespace RwsmsClient.Models;

public class EnvironmentInfo
{
    public string OsVersion { get; set; } = string.Empty;
    public string MachineName { get; set; } = string.Empty;
    public int ProcessorCount { get; set; }
}
