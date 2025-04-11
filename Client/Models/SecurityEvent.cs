// Models/SecurityEvent.cs

namespace Client
{
    public class SecurityEvent
    {
        public string? Sid { get; set; }
        public int EventId { get; set; }
        public string? TimeCreated { get; set; }
        public string? Description { get; set; }
    }
}
