// NetworkLog.cs
namespace RwsmsClient.Models;

public class NetworkLog
{
    public string LocalAddress { get; set; } = string.Empty;
    public string RemoteAddress { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string Timestamp { get; set; } = string.Empty;
}
