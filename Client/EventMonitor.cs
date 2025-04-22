using System;
using System.Diagnostics;

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
            try
            {
                // Security Event Log
                EventLog securityLog = new EventLog("Security");
                securityLog.EntryWritten += async (sender, e) =>
                {
                    if (e.Entry.InstanceId is 4624 or 4625 or 4634 or 4672 or 4720 or 4722 or 4728 or 4738 or 4673 or 4674 or 4616 or 4688 or 4697)
                    {
                        var securityEvent = new SecurityEvent
                        {
                            Sid = sid,
                            EventId = e.Entry.InstanceId,
                            TimeCreated = e.Entry.TimeGenerated.ToString("o"),
                            Description = e.Entry.Message ?? "No description",
                            Source = "Security",
                            LogonType = e.Entry.InstanceId == 4624 ? GetLogonType(e.Entry) : null,
                            FailureReason = e.Entry.InstanceId == 4625 ? GetFailureReason(e.Entry) : null,
                            TargetAccount = e.Entry.InstanceId is 4720 or 4728 ? GetTargetAccount(e.Entry) : null,
                            GroupName = e.Entry.InstanceId == 4728 ? GetGroupName(e.Entry) : null,
                            PrivilegeName = e.Entry.InstanceId == 4673 ? GetPrivilegeName(e.Entry) : null,
                            ProcessName = e.Entry.InstanceId == 4688 ? GetProcessName(e.Entry) : null,
                            ServiceName = e.Entry.InstanceId == 4697 ? GetServiceName(e.Entry) : null
                        };
                        await _apiClient.SendSecurityEvent(accessToken, securityEvent);
                    }
                };
                securityLog.EnableRaisingEvents = true;

                // Defender Event Log
                EventLog defenderLog = new EventLog("Microsoft-Windows-Windows Defender/Operational");
                defenderLog.EntryWritten += async (sender, e) =>
                {
                    if (e.Entry.InstanceId is 1006 or 1116)
                    {
                        var securityEvent = new SecurityEvent
                        {
                            Sid = sid,
                            EventId = e.Entry.InstanceId,
                            TimeCreated = e.Entry.TimeGenerated.ToString("o"),
                            Description = e.Entry.Message ?? "No description",
                            Source = "Defender"
                        };
                        await _apiClient.SendSecurityEvent(accessToken, securityEvent);
                    }
                };
                defenderLog.EnableRaisingEvents = true;

                // Firewall Event Log
                EventLog firewallLog = new EventLog("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall");
                firewallLog.EntryWritten += async (sender, e) =>
                {
                    if (e.Entry.InstanceId is 2003 or 2004)
                    {
                        var securityEvent = new SecurityEvent
                        {
                            Sid = sid,
                            EventId = e.Entry.InstanceId,
                            TimeCreated = e.Entry.TimeGenerated.ToString("o"),
                            Description = e.Entry.Message ?? "No description",
                            Source = "Firewall"
                        };
                        await _apiClient.SendSecurityEvent(accessToken, securityEvent);
                    }
                };
                firewallLog.EnableRaisingEvents = true;

                Console.WriteLine("Monitoring Security, Defender, and Firewall Event Logs for critical events...");
            }
            catch (SecurityException ex)
            {
                Console.WriteLine($"Security error accessing Event Log: {ex.Message}. Run as Administrator or ensure the account has 'Event Log Readers' permissions.");
                throw;
            }
        }

        private string? GetLogonType(EventLogEntry entry)
        {
            try
            {
                // Parse Logon Type from Message (e.g., "Logon Type: 2" for Interactive)
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
                // Parse Failure Reason from Message (e.g., "Failure Reason: Unknown user name or bad password")
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
                // Parse Target Account Name from Message (e.g., "Account Name: testuser")
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
                // Parse Group Name from Message (e.g., "Group Name: Administrators")
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
                // Parse Privilege Name from Message (e.g., "Privileges: SeBackupPrivilege")
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
                // Parse Process Name from Message (e.g., "New Process Name: C:\Windows\System32\cmd.exe")
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
                // Parse Service Name from Message (e.g., "Service Name: TestService")
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