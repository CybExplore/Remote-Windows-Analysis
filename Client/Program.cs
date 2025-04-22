// Program.cs

// using Microsoft.Extensions.DependencyInjection;
// using Microsoft.Extensions.Hosting;

// namespace Client
// {
//     class Program
//     {
//         static async Task Main(string[] args)
//         {
//             await Host.CreateDefaultBuilder(args)
//                 .UseWindowsService()
//                 .ConfigureServices((hostContext, services) =>
//                 {
//                     services.AddHostedService<Worker>();
//                     services.AddSingleton<CredentialManager>();
//                     services.AddSingleton<SystemInfoCollector>();
//                     services.AddSingleton<ApiClient>(sp => new ApiClient(hostContext.Configuration["ApiSettings:BaseUrl"] ?? "http://localhost:8000"));
//                     services.AddSingleton<EventMonitor>();
//                 })
//                 .Build()
//                 .RunAsync();
//         }
//     }
// }


using Microsoft.Extensions.Configuration;
using System;
using System.Threading.Tasks;

namespace Client
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Starting Remote Windows Security Management Client...");

            IConfiguration config = new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();
            string apiBaseUrl = config["ApiSettings:BaseUrl"] ?? "http://localhost:8000";

            var credentialManager = new CredentialManager();
            var systemInfoCollector = new SystemInfoCollector();
            var apiClient = new ApiClient(apiBaseUrl);
            var eventMonitor = new EventMonitor(apiClient);

            var (sid, clientId, clientSecret) = credentialManager.LoadCredentials();
            bool isNewAccount = sid == null;

            if (isNewAccount)
            {
                Console.Write("Enter your email address: ");
                string? email = Console.ReadLine();
                if (string.IsNullOrEmpty(email) || !CredentialManager.IsValidEmail(email))
                {
                    Console.WriteLine("A valid email address is required.");
                    return;
                }

                var userAccount = systemInfoCollector.GetUserAccountInfo();
                if (userAccount == null || string.IsNullOrEmpty(userAccount.Sid))
                {
                    Console.WriteLine("Failed to retrieve user account info.");
                    return;
                }

                userAccount.Email = email;
                userAccount.Password = CredentialManager.GenerateRandomPassword();
                userAccount.ClientId = CredentialManager.GenerateClientId();
                userAccount.ClientSecret = CredentialManager.GenerateClientSecret();

                bool success = await apiClient.CreateDjangoAccount(userAccount);
                if (success)
                {
                    Console.WriteLine($"Account created successfully!\nSID: {userAccount.Sid}\nClient ID: {userAccount.ClientId}\nClient Secret: {userAccount.ClientSecret}");
                    credentialManager.SaveCredentials(userAccount.Sid, userAccount.ClientId, userAccount.ClientSecret);
                    if (Environment.UserInteractive)
                    {
                        ApiClient.LaunchBrowser("http://localhost:3000/login");
                    }
                    sid = userAccount.Sid;
                    clientId = userAccount.ClientId;
                    clientSecret = userAccount.ClientSecret;
                }
                else
                {
                    Console.WriteLine("Failed to create account.");
                    return;
                }
            }

            string? accessToken = null;
            if (clientId != null && clientSecret != null)
            {
                accessToken = await apiClient.GetOAuthTokenWithClientCredentials(clientId, clientSecret);
            }
            else
            {
                Console.WriteLine("Client ID or Client Secret is null; cannot obtain OAuth token.");
            }

            if (!string.IsNullOrEmpty(accessToken))
            {
                Console.WriteLine("OAuth2 token obtained successfully!");
                if (sid != null)
                {
                    // Send Server Info
                    var serverInfo = systemInfoCollector.GetServerInfo(sid);
                    try
                    {
                        await apiClient.SendServerInfo(accessToken, serverInfo);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to send server info: {ex.Message}. Continuing with event monitoring...");
                    }

                    // Send Firewall Status
                    var firewallStatus = systemInfoCollector.GetFirewallStatus(sid);
                    try
                    {
                        await apiClient.SendFirewallStatus(accessToken, firewallStatus);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to send firewall status: {ex.Message}. Continuing with event monitoring...");
                    }

                    // Start Event Monitoring
                    try
                    {
                        eventMonitor.Start(sid, accessToken);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to start event monitoring: {ex.Message}. Ensure the application is run as Administrator.");
                    }
                }
                else
                {
                    Console.WriteLine("SID is null; cannot send data.");
                }
            }
            else
            {
                Console.WriteLine("Failed to obtain OAuth2 token.");
            }

            Console.WriteLine("Monitoring started. Press Ctrl+C to exit...");
            await Task.Delay(-1);
        }
    }
}

