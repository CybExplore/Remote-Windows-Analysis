using Microsoft.Extensions.Configuration;
using System;
using System.Threading.Tasks;
using Client.Models;

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
            string apiBaseUrl = config["ApiSettings:BaseUrl"] ?? "http://localhost:8000/";

            var credentialManager = new CredentialManager();
            var systemInfoCollector = new SystemInfoCollector();
            var apiClient = new ApiClient(apiBaseUrl);
            var eventMonitor = new EventMonitor(apiClient);

            var (sid, clientId, clientSecret, password) = credentialManager.LoadCredentials();
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
                if (string.IsNullOrEmpty(userAccount.Sid))
                {
                    Console.WriteLine("Failed to retrieve user account info.");
                    return;
                }

                userAccount.Email = email;
                userAccount.ClientId = CredentialManager.GenerateClientId();
                userAccount.ClientSecret = CredentialManager.GenerateClientSecret();

                bool success = await apiClient.CreateDjangoAccount(userAccount);
                if (success)
                {
                    Console.WriteLine($"Account created successfully!\nSID: {userAccount.Sid}\nClient ID: {userAccount.ClientId}\nClient Secret: {userAccount.ClientSecret}");
                    Console.WriteLine("Check your email for a temporary password.");
                    Console.Write("Enter the temporary password received via email: ");
                    userAccount.Password = Console.ReadLine();
                    if (string.IsNullOrEmpty(userAccount.Password))
                    {
                        Console.WriteLine("A valid temporary password is required.");
                        return;
                    }

                    credentialManager.SaveCredentials(userAccount.Sid, userAccount.ClientId, userAccount.ClientSecret, userAccount.Password);
                    if (Environment.UserInteractive)
                    {
                        ApiClient.LaunchBrowser("http://localhost:3000/login");
                    }
                    sid = userAccount.Sid;
                    clientId = userAccount.ClientId;
                    clientSecret = userAccount.ClientSecret;
                    password = userAccount.Password;
                }
                else
                {
                    Console.WriteLine("Failed to create account.");
                    return;
                }
            }

            string? accessToken = await apiClient.GetOAuthTokenWithPassword(clientId!, clientSecret!, sid!, password!);
            if (!string.IsNullOrEmpty(accessToken) && !string.IsNullOrEmpty(sid))
            {
                Console.WriteLine("OAuth2 token obtained successfully!");
                var serverInfo = systemInfoCollector.GetServerInfo(sid);
                serverInfo.ClientId = clientId;
                serverInfo.ClientSecret = clientSecret;
                try
                {
                    await apiClient.SendServerInfo(accessToken, serverInfo);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to send server info: {ex.Message}");
                }

                var firewallStatus = systemInfoCollector.GetFirewallStatus(sid);
                firewallStatus.ClientId = clientId;
                firewallStatus.ClientSecret = clientSecret;
                try
                {
                    await apiClient.SendFirewallStatus(accessToken, firewallStatus);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to send firewall status: {ex.Message}");
                }

                try
                {
                    eventMonitor.Start(sid, accessToken, clientId!, clientSecret!);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to start event monitoring: {ex.Message}. Ensure the application is run as Administrator.");
                }
            }
            else
            {
                Console.WriteLine("Failed to obtain OAuth2 token or SID is null.");
            }

            Console.WriteLine("Monitoring started. Press Ctrl+C to exit...");
            await Task.Delay(-1);
        }
    }
}
