// Models/FirewallStatus.cs

namespace Client.Models
{
    public class FirewallStatus
    {
        public string? Sid { get; set; }
        public bool IsEnabled { get; set; }
        public string? Profile { get; set; }
        public DateTime Timestamp { get; set; }
    }
}


