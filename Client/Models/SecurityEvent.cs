namespace Client.Models
{
    public class SecurityEvent
    {
        public string Sid { get; set; } = string.Empty; // Maps to 'client' (SID)
        public int EventId { get; set; } // Changed to int to match Django IntegerField
        public DateTime TimeCreated { get; set; } // Changed to DateTime to match Django DateTimeField
        public string Description { get; set; } = string.Empty;
        public string? Source { get; set; }
        public string? LogonType { get; set; }
        public string? FailureReason { get; set; }
        public string? TargetAccount { get; set; }
        public string? GroupName { get; set; }
        public string? PrivilegeName { get; set; }
        public string? ProcessName { get; set; }
        public string? ServiceName { get; set; }
        public string? ClientId { get; set; } 
        public string? ClientSecret { get; set; } 
    }
}