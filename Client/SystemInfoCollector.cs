// // SystemInfoCollector.cs

// using System.Management;

// namespace Client
// {
//     public class SystemInfoCollector
//     {
//         public UserAccount? GetUserAccountInfo()
//         {
//             string currentUser = Environment.UserName;
//             string domain = Environment.UserDomainName;
//             bool isShuttingDown = Environment.HasShutdownStarted;

//             string query = $"SELECT * FROM Win32_Account WHERE Name='{currentUser}'";
//             var searcher = new ManagementObjectSearcher(query);

//             try
//             {
//                 using ManagementObjectCollection collection = searcher.Get();
//                 foreach (ManagementObject userAccount in collection)
//                 {
//                     var sid = userAccount["SID"]?.ToString();
//                     if (string.IsNullOrEmpty(sid))
//                     {
//                         Console.WriteLine("SID is empty; attempting to retrieve machine SID.");
//                         sid = new ManagementObjectSearcher("SELECT SID FROM Win32_ComputerSystem")
//                             .Get().Cast<ManagementObject>().FirstOrDefault()?["SID"]?.ToString() ?? "Unknown";
//                     }

//                     return new UserAccount
//                     {
//                         Sid = sid,
//                         SidType = userAccount["SIDType"]?.ToString() ?? "Unknown",
//                         AccountType = userAccount["AccountType"]?.ToString() ?? "Unknown",
//                         FullName = userAccount["FullName"]?.ToString() ?? "Unknown",
//                         Description = userAccount["Description"]?.ToString() ?? "",
//                         Caption = userAccount["Caption"]?.ToString() ?? "",
//                         Status = userAccount["Status"]?.ToString() ?? "Unknown",
//                         LocalAccount = (bool)(userAccount["LocalAccount"] ?? false),
//                         Domain = domain,
//                         IsShuttingDown = isShuttingDown,
//                         Email = "",
//                         Password = "",
//                         ClientId = "",
//                         ClientSecret = ""
//                     };
//                 }
//                 Console.WriteLine("No user account found for current user.");
//             }
//             catch (ManagementException ex)
//             {
//                 Console.WriteLine($"WMI query failed: {ex.Message}");
//             }
//             return null;
//         }

//         public ServerInfo GetServerInfo(string? sid)
//         {
//             return new ServerInfo
//             {
//                 Sid = sid ?? "Unknown",
//                 MachineName = Environment.MachineName,
//                 OsVersion = Environment.OSVersion.ToString(),
//                 ProcessorCount = Environment.ProcessorCount,
//                 Timestamp = DateTime.Now.ToString("o"),
//                 Is64Bit = Environment.Is64BitOperatingSystem
//             };
//         }
//     }
// }

using System;
using System.Management;
// using Client.Models;

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
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Firewall");
                var result = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
                if (result != null)
                {
                    status.IsEnabled = result["Enabled"]?.ToString() == "True";
                    status.Profile = result["Profile"]?.ToString();
                }
                else
                {
                    status.IsEnabled = false;
                    status.Profile = "Unknown";
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


