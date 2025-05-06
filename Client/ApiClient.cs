using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Client.Models;
using Newtonsoft.Json;

namespace Client
{
    public class ApiClient : IDisposable
    {
        private readonly HttpClient _client;
        private readonly string _apiBaseUrl;
        private string? _accessToken;
        private string? _refreshToken;

        public ApiClient(string apiBaseUrl)
        {
            _client = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            _apiBaseUrl = apiBaseUrl.EndsWith("/") ? apiBaseUrl : apiBaseUrl + "/";
            _client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        public async Task<bool> CreateDjangoAccount(UserAccount userAccount)
        {
            try
            {
                if (string.IsNullOrEmpty(userAccount.Sid) || string.IsNullOrEmpty(userAccount.Email))
                {
                    Console.WriteLine("Error: SID or Email is empty in CreateDjangoAccount.");
                    return false;
                }
                var payload = new
                {
                    email = userAccount.Email,
                    full_name = userAccount.FullName,
                    sid = userAccount.Sid,
                    profile = new
                    {
                        client_id = userAccount.ClientId ?? Guid.NewGuid().ToString(),
                        client_secret = userAccount.ClientSecret ?? Guid.NewGuid().ToString()
                    }
                };
                var content = new StringContent(JsonConvert.SerializeObject(payload), Encoding.UTF8, "application/json");
                Console.WriteLine($"Sending POST to {_apiBaseUrl}api/accounts/create-user/: {JsonConvert.SerializeObject(payload)}");
                var response = await _client.PostAsync($"{_apiBaseUrl}api/accounts/create-user/", content);
                var responseContent = await response.Content.ReadAsStringAsync();
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"Account created: {responseContent}");
                    return true;
                }
                Console.WriteLine($"Failed to create account: {response.StatusCode} - {responseContent}");
                Console.WriteLine($"Response headers: {response.Headers}");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating account: {ex.Message}");
                return false;
            }
        }

        public async Task<string?> GetOAuthTokenWithPassword(string clientId, string clientSecret, string sid, string password)
        {
            try
            {
                if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) || 
                    string.IsNullOrEmpty(sid) || string.IsNullOrEmpty(password))
                {
                    Console.WriteLine("Error: Missing client_id, client_secret, sid, or password in GetOAuthTokenWithPassword.");
                    return null;
                }
                var payload = new Dictionary<string, string>
                {
                    {"grant_type", "password"},
                    {"client_id", clientId},
                    {"client_secret", clientSecret},
                    {"username", sid},
                    {"password", password},
                    {"scope", "read write"}
                };
                var content = new FormUrlEncodedContent(payload);
                Console.WriteLine($"Sending POST to {_apiBaseUrl}api/oauth2/token/ with payload: {JsonConvert.SerializeObject(payload)}");
                var response = await _client.PostAsync($"{_apiBaseUrl}api/oauth2/token/", content);
                var responseContent = await response.Content.ReadAsStringAsync();
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"OAuth token response: {responseContent}");
                    var tokenData = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseContent);
                    _accessToken = tokenData?.GetValueOrDefault("access_token");
                    _refreshToken = tokenData?.GetValueOrDefault("refresh_token");
                    _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
                    return _accessToken;
                }
                Console.WriteLine($"Failed to get OAuth token: {response.StatusCode} - {responseContent}");
                Console.WriteLine($"Response headers: {response.Headers}");
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting OAuth token: {ex.Message}");
                return null;
            }
        }

        public async Task<string?> RefreshOAuthToken(string clientId, string clientSecret)
        {
            if (string.IsNullOrEmpty(_refreshToken))
            {
                Console.WriteLine("Error: No refresh token available in RefreshOAuthToken.");
                return null;
            }
            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
            {
                Console.WriteLine("Error: Missing client_id or client_secret in RefreshOAuthToken.");
                return null;
            }
            try
            {
                var payload = new Dictionary<string, string>
                {
                    {"grant_type", "refresh_token"},
                    {"client_id", clientId},
                    {"client_secret", clientSecret},
                    {"refresh_token", _refreshToken}
                };
                var content = new FormUrlEncodedContent(payload);
                Console.WriteLine($"Sending POST to {_apiBaseUrl}api/o/token/ with payload: {JsonConvert.SerializeObject(payload)}");
                var response = await _client.PostAsync($"{_apiBaseUrl}api/o/token/", content);
                var responseContent = await response.Content.ReadAsStringAsync();
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"OAuth token refreshed: {responseContent}");
                    var tokenData = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseContent);
                    _accessToken = tokenData?.GetValueOrDefault("access_token");
                    _refreshToken = tokenData?.GetValueOrDefault("refresh_token");
                    _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
                    return _accessToken;
                }
                Console.WriteLine($"Failed to refresh OAuth token: {response.StatusCode} - {responseContent}");
                Console.WriteLine($"Response headers: {response.Headers}");
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error refreshing OAuth token: {ex.Message}");
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
            await SendWithRetry($"{_apiBaseUrl}api/core/server-info/", accessToken, payload, serverInfo.ClientId, serverInfo.ClientSecret);
        }

        public async Task SendSecurityEvent(string accessToken, SecurityEvent securityEvent)
        {
            var payload = new
            {
                client = securityEvent.Sid,
                event_id = securityEvent.EventId,
                time_created = securityEvent.TimeCreated.ToString("o"),
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
            await SendWithRetry($"{_apiBaseUrl}api/core/events/", accessToken, payload, securityEvent.ClientId, securityEvent.ClientSecret);
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
            await SendWithRetry($"{_apiBaseUrl}api/core/firewall-status/", accessToken, payload, firewallStatus.ClientId, firewallStatus.ClientSecret);
        }

        private async Task SendWithRetry(string url, string accessToken, object payload, string? clientId, string? clientSecret)
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
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                    Console.WriteLine($"Sending POST to {url}: {JsonConvert.SerializeObject(payload)}");
                    var response = await _client.SendAsync(request);
                    var responseContent = await response.Content.ReadAsStringAsync();
                    if (response.IsSuccessStatusCode)
                    {
                        Console.WriteLine("Data sent successfully");
                        return;
                    }
                    Console.WriteLine($"Attempt {attempt} failed: {response.StatusCode} - {responseContent}");
                    Console.WriteLine($"Response headers: {response.Headers}");
                    if (response.StatusCode == System.Net.HttpStatusCode.InternalServerError)
                    {
                        await Task.Delay(1000 * attempt);
                        continue;
                    }
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized && clientId != null && clientSecret != null)
                    {
                        var newToken = await RefreshOAuthToken(clientId, clientSecret);
                        if (newToken != null)
                        {
                            accessToken = newToken;
                            continue;
                        }
                    }
                    throw new HttpRequestException($"Failed to send data: {response.StatusCode} - {responseContent}");
                }
                catch (HttpRequestException ex)
                {
                    Console.WriteLine($"Attempt {attempt} failed: {ex.Message}");
                    if (attempt == maxRetries)
                    {
                        throw new Exception($"Failed to send data after {maxRetries} attempts: {ex.Message}");
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

        public void Dispose()
        {
            _client.Dispose();
        }
    }
}