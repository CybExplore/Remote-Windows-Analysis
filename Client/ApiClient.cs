using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Client.Models;
using Newtonsoft.Json;

namespace Client
{
    public class ApiClient
    {
        private readonly HttpClient _client;
        private readonly string _apiBaseUrl;

        private string? _accessToken;
        private string? _refreshToken;

        public ApiClient(string apiBaseUrl)
        {
            _client = new HttpClient();
            _apiBaseUrl = apiBaseUrl.EndsWith("/") ? apiBaseUrl : apiBaseUrl + "/";
        }

        public async Task<(string? clientId, string? clientSecret)> GetClientCredentials(string sid)
        {
            try
            {
                var response = await _client.GetAsync($"{_apiBaseUrl}api/user-profile/{sid}/");
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var profile = JsonConvert.DeserializeObject<Dictionary<string, string>>(content);
                    return (profile?.GetValueOrDefault("client_id"), profile?.GetValueOrDefault("client_secret"));
                }
                Console.WriteLine($"Failed to get client credentials: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
                return (null, null);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting client credentials: {ex.Message}");
                return (null, null);
            }
        }

        public async Task<bool> CreateDjangoAccount(UserAccount userAccount)
        {
            try
            {
                var payload = new
                {
                    email = userAccount.Email,
                    password = userAccount.Password,
                    sid = userAccount.Sid,
                    profile = new
                    {
                        client_id = userAccount.ClientId,
                        client_secret = userAccount.ClientSecret
                    }
                };
                var content = new StringContent(JsonConvert.SerializeObject(payload), Encoding.UTF8, "application/json");
                Console.WriteLine($"Sending create user request: {JsonConvert.SerializeObject(payload)}");
                var response = await _client.PostAsync($"{_apiBaseUrl}api/create-user/", content);
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Account created: {responseContent}");
                    return true;
                }
                var errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Failed to create account: {response.StatusCode} - {errorContent}");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating account: {ex.Message}");
                return false;
            }
        }

        public async Task<string?> GetOAuthTokenWithClientCredentials(string clientId, string clientSecret)
        {
            try
            {
                var payload = new Dictionary<string, string>
                {
                    {"grant_type", "client_credentials"},
                    {"client_id", clientId},
                    {"client_secret", clientSecret}
                };
                var response = await _client.PostAsync($"{_apiBaseUrl}o/token/", new FormUrlEncodedContent(payload));
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"OAuth token response: {responseContent}");
                    var tokenData = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseContent);
                    return tokenData?.GetValueOrDefault("access_token");
                }
                Console.WriteLine($"Failed to get OAuth token: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting OAuth token: {ex.Message}");
                return null;
            }
        }

        public async Task SendServerInfo(string accessToken, ServerInfo serverInfo)
        {
            var payload = new
            {
                client = serverInfo.Sid,
                machine_name = serverInfo.MachineName,
                os_version = serverInfo.OsVersion,
                processor_count = serverInfo.ProcessorCount,
                timestamp = serverInfo.Timestamp.ToString("o"),
                is_64bit = serverInfo.Is64Bit
            };
            await SendWithRetry($"{_apiBaseUrl}api/server-info/", accessToken, payload);
        }

        public async Task SendSecurityEvent(string accessToken, SecurityEvent securityEvent)
        {
            var payload = new
            {
                client = securityEvent.Sid,
                event_id = securityEvent.EventId,
                time_created = securityEvent.TimeCreated,
                description = securityEvent.Description,
                source = securityEvent.Source,
                logon_type = securityEvent.LogonType,
                failure_reason = securityEvent.FailureReason,
                target_account = securityEvent.TargetAccount,
                group_name = securityEvent.GroupName,
                privilege_name = securityEvent.PrivilegeName,
                process_name = securityEvent.ProcessName,
                service_name = securityEvent.ServiceName
            };
            await SendWithRetry($"{_apiBaseUrl}api/events/", accessToken, payload);
        }

        public async Task SendFirewallStatus(string accessToken, FirewallStatus firewallStatus)
        {
            var payload = new
            {
                client = firewallStatus.Sid,
                is_enabled = firewallStatus.IsEnabled,
                profile = firewallStatus.Profile,
                timestamp = firewallStatus.Timestamp.ToString("o")
            };
            await SendWithRetry($"{_apiBaseUrl}api/firewall-status/", accessToken, payload);
        }

        private async Task SendWithRetry(string url, string accessToken, object payload)
        {
            int maxRetries = 3;
            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    var content = new StringContent(JsonConvert.SerializeObject(payload), Encoding.UTF8, "application/json");
                    var request = new HttpRequestMessage(HttpMethod.Post, url)
                    {
                        Content = content
                    };
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                    Console.WriteLine($"Sending to {url}: {JsonConvert.SerializeObject(payload)}");
                    Console.WriteLine($"Using OAuth token: {(accessToken != null ? accessToken.Substring(0, Math.Min(accessToken.Length, 20)) : "null")}...");
                    var response = await _client.SendAsync(request);
                    response.EnsureSuccessStatusCode();
                    Console.WriteLine("Data sent successfully");
                    return;
                }
                catch (HttpRequestException ex)
                {
                    Console.WriteLine($"Attempt {attempt} failed: {ex.Message}");
                    if (attempt == maxRetries)
                    {
                        throw new Exception($"Failed to send data after {maxRetries} attempts.");
                    }
                    await Task.Delay(1000 * attempt);
                }
            }
        }

        public static void LaunchBrowser(string url)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error launching browser: {ex.Message}");
            }
        }
    }
}

