namespace Client.Models
{
    public class ServerInfo
    {
        public string Sid { get; set; } = string.Empty; // Maps to 'client' (SID)
        public string MachineName { get; set; } = string.Empty;
        public string OsVersion { get; set; } = string.Empty;
        public int ProcessorCount { get; set; }
        public DateTime Timestamp { get; set; }
        public bool Is64Bit { get; set; }
        public string? ClientId { get; set; } // Restored for OAuth2
        public string? ClientSecret { get; set; } // Restored for OAuth2
    }
}