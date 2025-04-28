using System;
using System.Management;
using Client.Models;
using Microsoft.Win32;

namespace Client
{
    public class SystemInfoCollector
    {
        public UserAccount GetUserAccountInfo()
        {
            var account = new UserAccount();
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                var result = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
                if (result != null)
                {
                    account.Sid = GetSidForCurrentUser();
                    account.MachineName = result["Name"]?.ToString() ?? Environment.MachineName;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error collecting user account info: {ex.Message}");
            }
            return account;
        }

        public ServerInfo GetServerInfo(string sid)
        {
            var serverInfo = new ServerInfo
            {
                Sid = sid,
                MachineName = Environment.MachineName,
                OsVersion = Environment.OSVersion.ToString(),
                ProcessorCount = Environment.ProcessorCount,
                Timestamp = DateTime.Now,
                Is64Bit = Environment.Is64BitOperatingSystem
            };
            return serverInfo;
        }

        public FirewallStatus GetFirewallStatus(string sid)
        {
            var status = new FirewallStatus
            {
                Sid = sid,
                Timestamp = DateTime.Now
            };
            try
            {
                // Use MSFT_NetFirewallProfile in root\StandardCimv2 namespace
                using var searcher = new ManagementObjectSearcher(
                    @"root\StandardCimv2",
                    "SELECT * FROM MSFT_NetFirewallProfile WHERE Enabled = 1"
                );
                var result = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
                if (result != null)
                {
                    status.IsEnabled = true;
                    status.Profile = result["Name"]?.ToString() ?? "Unknown";
                }
                else
                {
                    status.IsEnabled = false;
                    status.Profile = "None";
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error collecting firewall status: {ex.Message}");
                status.IsEnabled = false;
                status.Profile = "Error";
            }
            return status;
        }

        private string GetSidForCurrentUser()
        {
            try
            {
                return System.Security.Principal.WindowsIdentity.GetCurrent().User?.ToString() ?? "";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting SID: {ex.Message}");
                return "";
            }
        }
    }
}
