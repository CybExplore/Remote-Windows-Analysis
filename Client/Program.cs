namespace Client;

using System;
using System.Management; // For WMI
using System.Net.Http;   // For HTTP requests
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Newtonsoft.Json; // For JSON serialization (assumes Newtonsoft.Json is installed)
using System.Runtime.Versioning;

class Program
{
    private static readonly HttpClient client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    private static readonly string apiBaseUrl = "http://localhost:8000"; // Configurable base URL

    [SupportedOSPlatform("windows")]
    static async Task Main(string[] args)
    {
        Console.WriteLine("Starting Remote Windows Security Management Client...");

        // Load or generate credentials
        var (sid, clientId, clientSecret) = LoadCredentials();
        bool isNewAccount = sid == null;

        if (isNewAccount)
        {
            // New account setup
            string currentUser = Environment.UserName;
            string domain = Environment.UserDomainName;
            bool is_shutting_down = Environment.HasShutdownStarted;

            string query = $"SELECT * FROM Win32_Account WHERE Name='{currentUser}'";
            var searcher = new ManagementObjectSearcher(query);

            string sid_type = null, account_type = null, full_name = "Unknown", description = null, caption = null, status = null;
            bool local_account = false;

            try
            {
                using (ManagementObjectCollection collection = searcher.Get())
                {
                    foreach (ManagementObject userAccount in collection)
                    {
                        sid = userAccount["SID"]?.ToString();
                        sid_type = userAccount["SIDType"]?.ToString();
                        account_type = userAccount["AccountType"]?.ToString();
                        full_name = userAccount["FullName"]?.ToString() ?? "Unknown";
                        description = userAccount["Description"]?.ToString();
                        caption = userAccount["Caption"]?.ToString();
                        status = userAccount["Status"]?.ToString();
                        local_account = (bool)userAccount["LocalAccount"];
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
            clientId = GenerateClientId();
            clientSecret = GenerateClientSecret();

            bool success = await CreateDjangoAccount(sid, email, password, full_name, domain, account_type, caption, sid_type, description, status, local_account, is_shutting_down, clientId, clientSecret);
            if (success)
            {
                Console.WriteLine($"Account created successfully!\nSID: {sid}\nPassword: {password}\nClient ID: {clientId}\nClient Secret: {clientSecret}");
                Console.WriteLine("Save these credentials securely; the password is for initial login only.");
                SaveCredentials(sid, clientId, clientSecret);
            }
            else
            {
                Console.WriteLine("Failed to create the account.");
                return;
            }
        }

        // Get OAuth2 token and send server info
        string accessToken = await GetOAuthTokenWithClientCredentials(clientId, clientSecret);
        if (!string.IsNullOrEmpty(accessToken))
        {
            Console.WriteLine("OAuth2 token obtained successfully!");
            await SendServerInfo(accessToken, sid);
        }
        else
        {
            Console.WriteLine("Failed to obtain OAuth2 token.");
        }

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }

    static string GenerateRandomPassword(int length = 12)
    {
        const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()<>";
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

    static string GenerateClientId()
    {
        return Guid.NewGuid().ToString("N"); // 32-character unique ID (e.g., "550e8400e29b41d4a716446655440000")
    }

    static string GenerateClientSecret()
    {
        byte[] randomBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
        return Convert.ToBase64String(randomBytes); // 44-character secure secret (e.g., "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0Cg==")
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

    static async Task<bool> CreateDjangoAccount(string sid, string email, string password, string full_name, string domain,
        string account_type, string caption, string sid_type, string description, string status, bool local_account, bool is_shutting_down,
        string clientId, string clientSecret)
    {
        var payload = new
        {
            sid,
            email,
            password,
            full_name,
            domain,
            account_type,
            caption,
            sid_type,
            description,
            status,
            local_account,
            is_shutting_down,
            profile = new { description }, // Add more profile fields if needed
            client_id = clientId,
            client_secret = clientSecret
        };

        var json = JsonConvert.SerializeObject(payload);
        Console.WriteLine($"Sending payload to server: {json}");
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            var response = await client.PostAsync($"{apiBaseUrl}/api/create-user/", content);
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("Server response: " + await response.Content.ReadAsStringAsync());
            
                // Launch browser after successful account creation
                LaunchBrowser("http://localhost:3000/login");
                return true;
            }
            else
            {
                string errorMessage = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Error creating account: {response.StatusCode} - {errorMessage}");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error sending request: {ex.Message}");
            return false;
        }
    }

    // // Helper method to launch default browser
    static void LaunchBrowser(string url)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
            Console.WriteLine($"Launched browser with URL: {url}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to launch browser: {ex.Message}");
        }
    }

    static void SaveCredentials(string sid, string clientId, string clientSecret)
    {
        // For demo: store in plain text file; in production, use secure storage (e.g., Windows Credential Manager)
        string credentials = $"SID={sid}\nCLIENT_ID={clientId}\nCLIENT_SECRET={clientSecret}";
        File.WriteAllText("credentials.txt", credentials);
        Console.WriteLine("Credentials saved to credentials.txt (for demo only; use secure storage in production)");
    }

    static (string sid, string clientId, string clientSecret) LoadCredentials()
    {
        if (File.Exists("credentials.txt"))
        {
            var lines = File.ReadAllLines("credentials.txt");
            if (lines.Length >= 3)
            {
                string sid = lines[0].Split('=')[1];
                string clientId = lines[1].Split('=')[1];
                string clientSecret = lines[2].Split('=')[1];
                Console.WriteLine("Loaded credentials from credentials.txt");
                return (sid, clientId, clientSecret);
            }
        }
        Console.WriteLine("No existing credentials found; proceeding with new account creation");
        return (null, null, null);
    }

    static async Task<string> GetOAuthTokenWithClientCredentials(string clientId, string clientSecret)
    {
        var payload = new Dictionary<string, string>
        {
            {"grant_type", "client_credentials"},
            {"client_id", clientId},
            {"client_secret", clientSecret}
        };

        try
        {
            var response = await client.PostAsync($"{apiBaseUrl}/o/token/", new FormUrlEncodedContent(payload));
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                dynamic data = JsonConvert.DeserializeObject(json);
                Console.WriteLine($"Token response: {json}");
                return data.access_token;
            }
            else
            {
                Console.WriteLine($"Token request failed: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
                return null;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error getting token: {ex.Message}");
            return null;
        }
    }

    static async Task SendServerInfo(string accessToken, string sid)
    {
        var payload = new
        {
            sid,
            machine_name = Environment.MachineName,
            os_version = Environment.OSVersion.ToString(),
            processor_count = Environment.ProcessorCount,
            timestamp = DateTime.Now.ToString("o"),
            is_64bit = Environment.Is64BitOperatingSystem
        };
        var json = JsonConvert.SerializeObject(payload);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        try
        {
            var response = await client.PostAsync($"{apiBaseUrl}/api/server-info/", content);
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("Server info sent successfully: " + await response.Content.ReadAsStringAsync());
            }
            else
            {
                Console.WriteLine($"Failed to send server info: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error sending server info: {ex.Message}");
        }
    }
}

