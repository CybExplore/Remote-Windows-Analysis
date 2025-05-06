using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Security;
using System.Threading.Tasks;
using Client.Models;

namespace Client
{
    public class EventMonitor
    {
        private readonly ApiClient _apiClient;
        private readonly ConcurrentQueue<SecurityEvent> _eventQueue = new();
        private readonly TimeSpan _batchInterval = TimeSpan.FromSeconds(10);

        public EventMonitor(ApiClient apiClient)
        {
            _apiClient = apiClient;
        }

        public void Start(string sid, string accessToken, string clientId, string clientSecret)
        {
            Task.Run(() => ProcessEventQueue(sid, accessToken, clientId, clientSecret));

            var logs = new[]
            {
                new { Name = "Security", EventIds = new long[] { 4624, 4625, 4634, 4672, 4720, 4722, 4728, 4738, 4673, 4674, 4616, 4688, 4697 } },
                new { Name = "Microsoft-Windows-Windows Defender/Operational", EventIds = new long[] { 1006, 1116 } },
                new { Name = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", EventIds = new long[] { 2003, 2004 } }
            };

            foreach (var log in logs)
            {
                try
                {
                    bool logExists = false;
                    try
                    {
                        using (var session = new EventLogSession())
                        {
                            logExists = session.GetLogNames().Contains(log.Name, StringComparer.OrdinalIgnoreCase);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error checking existence of Event Log '{log.Name}': {ex.Message}");
                    }

                    if (!logExists)
                    {
                        Console.WriteLine($"Event log '{log.Name}' does not exist. Skipping...");
                        continue;
                    }

                    EventLog eventLog = new EventLog(log.Name);
                    eventLog.EntryWritten += (sender, e) =>
                    {
                        if (log.EventIds.Contains(e.Entry.InstanceId))
                        {
                            if (e.Entry.InstanceId > int.MaxValue)
                            {
                                Console.WriteLine($"Warning: Event ID {e.Entry.InstanceId} exceeds int range. Truncating to {int.MaxValue}.");
                            }
                            var securityEvent = new SecurityEvent
                            {
                                Sid = sid,
                                EventId = (int)e.Entry.InstanceId, // Cast long to int
                                TimeCreated = e.Entry.TimeGenerated, // Use DateTime directly
                                Description = e.Entry.Message ?? "No description",
                                Source = log.Name.Split('/')[0],
                                LogonType = e.Entry.InstanceId == 4624 ? GetLogonType(e.Entry) : null,
                                FailureReason = e.Entry.InstanceId == 4625 ? GetFailureReason(e.Entry) : null,
                                TargetAccount = e.Entry.InstanceId is 4720 or 4728 ? GetTargetAccount(e.Entry) : null,
                                GroupName = e.Entry.InstanceId == 4728 ? GetGroupName(e.Entry) : null,
                                PrivilegeName = e.Entry.InstanceId == 4673 ? GetPrivilegeName(e.Entry) : null,
                                ProcessName = e.Entry.InstanceId == 4688 ? GetProcessName(e.Entry) : null,
                                ServiceName = e.Entry.InstanceId == 4697 ? GetServiceName(e.Entry) : null,
                                ClientId = clientId,
                                ClientSecret = clientSecret
                            };
                            _eventQueue.Enqueue(securityEvent);
                            Console.WriteLine($"Queued security event: {securityEvent.EventId} from {log.Name}");
                        }
                    };
                    eventLog.EnableRaisingEvents = true;
                    Console.WriteLine($"Monitoring {log.Name} for critical events...");
                }
                catch (SecurityException ex)
                {
                    Console.WriteLine($"Security error accessing Event Log '{log.Name}': {ex.Message}. Run as Administrator or ensure the account has 'Event Log Readers' permissions.");
                    continue;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error accessing Event Log '{log.Name}': {ex.Message}");
                    continue;
                }
            }

            Console.WriteLine("Monitoring started for available Event Logs. Press Ctrl+C to exit...");
        }

        private async Task ProcessEventQueue(string sid, string accessToken, string clientId, string clientSecret)
        {
            while (true)
            {
                if (_eventQueue.TryDequeue(out var securityEvent))
                {
                    try
                    {
                        await _apiClient.SendSecurityEvent(accessToken, securityEvent);
                        Console.WriteLine($"Sent security event: {securityEvent.EventId}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to send security event: {ex.Message}");
                    }
                }
                else
                {
                    await Task.Delay(_batchInterval);
                }
            }
        }

        private string? GetLogonType(EventLogEntry entry)
        {
            try
            {
                string[] lines = entry.Message.Split('\n');
                foreach (string line in lines)
                {
                    if (line.Contains("Logon Type:"))
                    {
                        string[] parts = line.Split(':');
                        if (parts.Length > 1)
                        {
                            string typeNum = parts[1].Trim();
                            return typeNum switch
                            {
                                "2" => "Interactive",
                                "3" => "Network",
                                "7" => "Unlock",
                                "10" => "RemoteInteractive",
                                _ => typeNum
                            };
                        }
                    }
                }
                return "Unknown";
            }
            catch
            {
                return "Error";
            }
        }

        private string? GetFailureReason(EventLogEntry entry)
        {
            try
            {
                string[] lines = entry.Message.Split('\n');
                foreach (string line in lines)
                {
                    if (line.Contains("Failure Reason:"))
                    {
                        return line.Split(':')[1].Trim();
                    }
                }
                return "Unknown";
            }
            catch
            {
                return "Error";
            }
        }

        private string? GetTargetAccount(EventLogEntry entry)
        {
            try
            {
                string[] lines = entry.Message.Split('\n');
                foreach (string line in lines)
                {
                    if (line.Contains("Account Name:"))
                    {
                        return line.Split(':')[1].Trim();
                    }
                }
                return "Unknown";
            }
            catch
            {
                return "Error";
            }
        }

        private string? GetGroupName(EventLogEntry entry)
        {
            try
            {
                string[] lines = entry.Message.Split('\n');
                foreach (string line in lines)
                {
                    if (line.Contains("Group Name:"))
                    {
                        return line.Split(':')[1].Trim();
                    }
                }
                return "Unknown";
            }
            catch
            {
                return "Error";
            }
        }

        private string? GetPrivilegeName(EventLogEntry entry)
        {
            try
            {
                string[] lines = entry.Message.Split('\n');
                foreach (string line in lines)
                {
                    if (line.Contains("Privileges:"))
                    {
                        return line.Split(':')[1].Trim();
                    }
                }
                return "Unknown";
            }
            catch
            {
                return "Error";
            }
        }

        private string? GetProcessName(EventLogEntry entry)
        {
            try
            {
                string[] lines = entry.Message.Split('\n');
                foreach (string line in lines)
                {
                    if (line.Contains("New Process Name:"))
                    {
                        return line.Split(':')[1].Trim();
                    }
                }
                return "Unknown";
            }
            catch
            {
                return "Error";
            }
        }

        private string? GetServiceName(EventLogEntry entry)
        {
            try
            {
                string[] lines = entry.Message.Split('\n');
                foreach (string line in lines)
                {
                    if (line.Contains("Service Name:"))
                    {
                        return line.Split(':')[1].Trim();
                    }
                }
                return "Unknown";
            }
            catch
            {
                return "Error";
            }
        }
    }
}