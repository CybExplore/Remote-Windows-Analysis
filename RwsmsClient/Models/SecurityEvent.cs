namespace RwsmsClient.Models;

public class SecurityEvent
{
    public string EventType { get; set; } = string.Empty;
    public int EventId { get; set; }
    public string Source { get; set; } = string.Empty;
    public string Timestamp { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
}