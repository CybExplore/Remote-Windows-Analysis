namespace Client;

using System;
using System.Management; // For WMI
using System.Net.Http;   // For HTTP requests
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Versioning; // For SupportedOSPlatform attribute

class Program
{
    [SupportedOSPlatform("windows")]
    static async Task Main(string[] args)
    {
        string currentUser = Environment.UserName;
        string domain = Environment.UserDomainName;

        bool is_shutting_down = Environment.HasShutdownStarted;

        string query = $"SELECT * FROM Win32_Account WHERE Name='{currentUser}'";
        var searcher = new ManagementObjectSearcher(query);

        string sid = null;
        string sid_type = null;
        string account_type = null;
        string full_name = "Unknown";
        string description = null;
        string caption = null;
        bool local_account;

        try
        {
            using (ManagementObjectCollection collection = searcher.Get())
            {
                foreach (ManagementObject userAccount in collection)
                {
                    sid = userAccount["SID"].ToString();
                    sid_type = userAccount["SIDType"].ToString();
                    account_type = userAccount["AccountType"].ToString();
                    full_name = userAccount["FullName"]?.ToString() ?? "Unknown";
                    description = userAccount["Description"]?.ToString();
                    caption = userAccount["Caption"]?.ToString();
                    // local_account = userAccount["LocalAccount"];

                    Console.WriteLine();
                    Console.WriteLine(userAccount["LocalAccount"]);
                    Console.WriteLine(userAccount["Status"]);
                }
            }
        }
        catch (ManagementException ex)
        {
            Console.WriteLine($"WMI query failed: {ex.Message}");
            return;
        }

        if (string.IsNullOrEmpty(sid))
        {
            Console.WriteLine("Failed to retrieve the user's SID.");
            return;
        }

        Console.Write("Enter your email address: ");
        string email = Console.ReadLine();

        if (string.IsNullOrEmpty(email) || !IsValidEmail(email))
        {
            Console.WriteLine("A valid email address is required.");
            return;
        }

        string password = GenerateRandomPassword();
        Console.WriteLine($"Your generated password is: {password}");

        bool success = await CreateDjangoAccount(sid, email, password, full_name, domain, account_type, caption, sid_type, is_shutting_down);
        if (success)
        {
            Console.WriteLine("Account created successfully!");
        }
        else
        {
            Console.WriteLine("Failed to create the account.");
        }
        Console.ReadKey();
    }

    static string GenerateRandomPassword(int length = 12)
    {
        const string validChars = "qwertyuiopasdfghjklzxcvbnm1234567890QWERTYUIOPASDFGHJKLZXCVBNM!@#$%^&*()<>";
        byte[] randomBytes = new byte[length];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
        var password = new StringBuilder(length);
        foreach (byte b in randomBytes)
        {
            password.Append(validChars[b % validChars.Length]);
        }
        return password.ToString();
    }

    static bool IsValidEmail(string email)
    {
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }

    static async Task<bool> CreateDjangoAccount(string sid, string email, string password, string full_name, string domain, string account_type, string caption, string sid_type, bool is_shutting_down)
    {
        using (var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) })
        {
            var payload = new { sid, email, password, full_name, domain, account_type, caption, sid_type, is_shutting_down };
            var json = Newtonsoft.Json.JsonConvert.SerializeObject(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            try
            {
                var response = await client.PostAsync("http://localhost:8000/api/users/", content);
                if (response.IsSuccessStatusCode)
                {
                    return true;
                }
                else
                {
                    string errorMessage = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Error: {response.StatusCode} - {errorMessage}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending request: {ex.Message}");
                return false;
            }
        }
    }
}



