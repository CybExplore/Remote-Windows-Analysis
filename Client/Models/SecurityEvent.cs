// // Models/SecurityEvent.cs

// using Newtonsoft.Json;

// namespace Client
// {
//     public class SecurityEvent
//     {
//         [JsonProperty("sid")] public string? Sid { get; set; }
//         [JsonProperty("event_id")] public long EventId { get; set; }
//         [JsonProperty("time_created")] public string? TimeCreated { get; set; }
//         [JsonProperty("description")] public string? Description { get; set; }
//     }
// }



namespace Client.Models
{
    public class SecurityEvent
    {
        public string Sid { get; set; } = string.Empty;
        public long EventId { get; set; }
        public string TimeCreated { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string? Source { get; set; }
        public string? LogonType { get; set; }
        public string? FailureReason { get; set; }
        public string? TargetAccount { get; set; }
        public string? GroupName { get; set; }
        public string? PrivilegeName { get; set; }
        public string? ProcessName { get; set; }
        public string? ServiceName { get; set; }
    }
}

