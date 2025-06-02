// FileLog.cs
namespace RwsmsClient.Models;

public class FileLog
{
    public string EventType { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string ChangeType { get; set; } = string.Empty;
    public string OldPath { get; set; } = string.Empty;
    public string Timestamp { get; set; } = string.Empty;
}
