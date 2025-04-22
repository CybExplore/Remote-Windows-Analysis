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


using Newtonsoft.Json;

namespace Client
{
    public class SecurityEvent
    {
        [JsonProperty("sid")] public string? Sid { get; set; }
        [JsonProperty("event_id")] public long EventId { get; set; }
        [JsonProperty("time_created")] public string? TimeCreated { get; set; }
        [JsonProperty("description")] public string? Description { get; set; }
    }
}

