// EventMonitor.cs

using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Client
{
    public class EventMonitor
    {
        private readonly ApiClient _apiClient;

        public EventMonitor(ApiClient apiClient)
        {
            _apiClient = apiClient;
        }

        public void Start(string sid, string accessToken)
        {
            EventLog eventLog = new("Security");
            eventLog.EntryWritten += async (sender, e) =>
            {
                var securityEvent = new SecurityEvent
                {
                    Sid = sid,
                    EventId = e.Entry.EventID,
                    TimeCreated = e.Entry.TimeGenerated.ToString("o"),
                    Description = e.Entry.Message ?? "No description"
                };
                await _apiClient.SendSecurityEvent(accessToken, securityEvent);
            };
            eventLog.EnableRaisingEvents = true;
            Console.WriteLine("Monitoring Security Event Log...");
        }
    }
}
