namespace Client.Models
{
    public class FirewallStatus
    {
        public string Sid { get; set; } = string.Empty; // Maps to 'client' (SID)
        public bool IsEnabled { get; set; }
        public string? Profile { get; set; }
        public DateTime Timestamp { get; set; }
        public string? ClientId { get; set; } // Restored for OAuth2
        public string? ClientSecret { get; set; } // Restored for OAuth2
    }
}
