// ProcessLog.cs
namespace RwsmsClient.Models;

public class ProcessLog
{
    public string Name { get; set; } = string.Empty;
    public int Pid { get; set; }
    public string Path { get; set; } = string.Empty;
    public string StartTime { get; set; } = string.Empty;
}
