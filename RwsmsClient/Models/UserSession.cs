// UserSession.cs
namespace RwsmsClient.Models;

public class UserSession
{
    public int SessionId { get; set; }
    public string StartTime { get; set; } = string.Empty;
}
