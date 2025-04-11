// SystemInfoCollector.cs

using System;
using System.Management;

namespace Client
{
    public class SystemInfoCollector
    {
        public UserAccount? GetUserAccountInfo()
        {
            string currentUser = Environment.UserName;
            string domain = Environment.UserDomainName;
            bool isShuttingDown = Environment.HasShutdownStarted;

            string query = $"SELECT * FROM Win32_Account WHERE Name='{currentUser}'";
            var searcher = new ManagementObjectSearcher(query);

            try
            {
                using ManagementObjectCollection collection = searcher.Get();
                foreach (ManagementObject userAccount in collection)
                {
                    return new UserAccount
                    {
                        Sid = userAccount["SID"]?.ToString() ?? "Unknown",
                        SidType = userAccount["SIDType"]?.ToString() ?? "Unknown",
                        AccountType = userAccount["AccountType"]?.ToString() ?? "Unknown",
                        FullName = userAccount["FullName"]?.ToString() ?? "Unknown",
                        Description = userAccount["Description"]?.ToString() ?? "",
                        Caption = userAccount["Caption"]?.ToString() ?? "",
                        Status = userAccount["Status"]?.ToString() ?? "Unknown",
                        LocalAccount = (bool)(userAccount["LocalAccount"] ?? false),
                        Domain = domain,
                        IsShuttingDown = isShuttingDown,
                        Email = "",
                        Password = "",
                        ClientId = "",
                        ClientSecret = ""
                    };
                }
            }
            catch (ManagementException ex)
            {
                Console.WriteLine($"WMI query failed: {ex.Message}");
            }
            return null;
        }

        public ServerInfo GetServerInfo(string? sid)
        {
            return new ServerInfo
            {
                Sid = sid ?? "Unknown",
                MachineName = Environment.MachineName,
                OsVersion = Environment.OSVersion.ToString(),
                ProcessorCount = Environment.ProcessorCount,
                Timestamp = DateTime.Now.ToString("o"),
                Is64Bit = Environment.Is64BitOperatingSystem
            };
        }
    }
}
