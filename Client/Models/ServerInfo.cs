// // Models/SecurityInfo.cs

// using Newtonsoft.Json;

// namespace Client
// {
//     public class ServerInfo
//     {
//         [JsonProperty("sid")] public string? Sid { get; set; }
//         [JsonProperty("machine_name")] public string? MachineName { get; set; }
//         [JsonProperty("os_version")] public string? OsVersion { get; set; }
//         [JsonProperty("processor_count")] public int ProcessorCount { get; set; }
//         [JsonProperty("timestamp")] public string? Timestamp { get; set; }
//         [JsonProperty("is_64bit")] public bool Is64Bit { get; set; }
//     }
// }


using Newtonsoft.Json;

namespace Client
{
    public class ServerInfo
    {
        [JsonProperty("sid")] public string? Sid { get; set; }
        [JsonProperty("machine_name")] public string? MachineName { get; set; }
        [JsonProperty("os_version")] public string? OsVersion { get; set; }
        [JsonProperty("processor_count")] public int ProcessorCount { get; set; }
        [JsonProperty("timestamp")] public string? Timestamp { get; set; }
        [JsonProperty("is_64bit")] public bool Is64Bit { get; set; }
    }
}

