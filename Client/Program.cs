// Program.cs

using System;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace Client
{
    class Program
    {
        [SupportedOSPlatform("windows")]
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
                Console.WriteLine("Registered Email is " + email);
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

                    ApiClient.LaunchBrowser("http://localhost:3000/login");

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

            string? accessToken = await apiClient.GetOAuthTokenWithClientCredentials(clientId, clientSecret);
            if (!string.IsNullOrEmpty(accessToken))
            {
                Console.WriteLine("OAuth2 token obtained successfully!");
                if (sid != null)
                {
                    var serverInfo = systemInfoCollector.GetServerInfo(sid);
                    await apiClient.SendServerInfo(accessToken, serverInfo);
                    eventMonitor.Start(sid, accessToken);
                }
                else
                {
                    Console.WriteLine("SID is null; cannot send server info.");
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

