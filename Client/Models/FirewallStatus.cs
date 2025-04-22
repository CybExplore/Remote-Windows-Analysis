// Models/FirewallStatus.cs

using System;

namespace Client
{
    public class FirewallStatus
    {
        public string Sid { get; set; }
        public bool IsEnabled { get; set; }
        public string? Profile { get; set; }
        public DateTime Timestamp { get; set; }
    }
}

