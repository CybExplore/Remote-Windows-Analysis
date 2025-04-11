// Models/SecurityInfo.cs

namespace Client
{
    public class ServerInfo
    {
        public string? Sid { get; set; }
        public string? MachineName { get; set; }
        public string? OsVersion { get; set; }
        public int ProcessorCount { get; set; }
        public string? Timestamp { get; set; }
        public bool Is64Bit { get; set; }
    }
}

