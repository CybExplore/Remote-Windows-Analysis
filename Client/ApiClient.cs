// // ApiClient.cs

// using System.Diagnostics;
// using System.Net.Http.Headers;
// using System.Text;
// using Newtonsoft.Json;

// namespace Client
// {
//     public class ApiClient : IDisposable
//     {
//         private readonly HttpClient _client;
//         private readonly string _apiBaseUrl;

//         public ApiClient(string apiBaseUrl)
//         {
//             _apiBaseUrl = apiBaseUrl;
//             _client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
//         }

//         public async Task<bool> CreateDjangoAccount(UserAccount account)
//         {
//             var json = JsonConvert.SerializeObject(account);
//             Console.WriteLine("Sending payload to /api/create-user/: " + json);
//             var content = new StringContent(json, Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
//             for (int attempt = 1; attempt <= 3; attempt++)
//             {
//                 try
//                 {
//                     var response = await _client.PostAsync($"{_apiBaseUrl}/api/create-user/", content);
//                     if (response.IsSuccessStatusCode)
//                     {
//                         Console.WriteLine("Account created: " + await response.Content.ReadAsStringAsync());
//                         return true;
//                     }
//                     Console.WriteLine($"Attempt {attempt} failed: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
//                     if (attempt < 3) await Task.Delay(1000);
//                 }
//                 catch (Exception ex)
//                 {
//                     Console.WriteLine($"Attempt {attempt} error: {ex.Message}");
//                     if (attempt < 3) await Task.Delay(1000);
//                 }
//             }
//             return false;
//         }

//         public static void LaunchBrowser(string url)
//         {
//             try
//             {
//                 Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
//             }
//             catch (Exception ex)
//             {
//                 Console.WriteLine($"Failed to launch browser: {ex.Message}");
//             }
//         }

//         public async Task<string?> GetOAuthTokenWithClientCredentials(string clientId, string clientSecret)
//         {
//             var payload = new Dictionary<string, string>
//             {
//                 {"grant_type", "client_credentials"},
//                 {"client_id", clientId},
//                 {"client_secret", clientSecret}
//             };
//             for (int attempt = 1; attempt <= 3; attempt++)
//             {
//                 try
//                 {
//                     var response = await _client.PostAsync($"{_apiBaseUrl}/o/token/", new FormUrlEncodedContent(payload));
//                     if (response.IsSuccessStatusCode)
//                     {
//                         var json = await response.Content.ReadAsStringAsync();
//                         var data = JsonConvert.DeserializeObject<TokenResponse>(json);
//                         return data?.AccessToken;
//                     }
//                     Console.WriteLine($"Token attempt {attempt} failed: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
//                     if (attempt < 3) await Task.Delay(1000);
//                 }
//                 catch (Exception ex)
//                 {
//                     Console.WriteLine($"Token attempt {attempt} error: {ex.Message}");
//                     if (attempt < 3) await Task.Delay(1000);
//                 }
//             }
//             return null;
//         }

//         public async Task SendServerInfo(string accessToken, ServerInfo serverInfo)
//         {
//             var json = JsonConvert.SerializeObject(serverInfo);
//             var content = new StringContent(json, Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
//             _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
//             try
//             {
//                 var response = await _client.PostAsync($"{_apiBaseUrl}/api/server-info/", content);
//                 Console.WriteLine(response.IsSuccessStatusCode
//                     ? "Server info sent successfully"
//                     : $"Failed to send server info: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
//             }
//             catch (Exception ex)
//             {
//                 Console.WriteLine($"Error sending server info: {ex.Message}");
//             }
//         }

//         public async Task SendSecurityEvent(string accessToken, SecurityEvent securityEvent)
//         {
//             var json = JsonConvert.SerializeObject(securityEvent);
//             var content = new StringContent(json, Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
//             _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
//             try
//             {
//                 var response = await _client.PostAsync($"{_apiBaseUrl}/api/events/", content);
//                 Console.WriteLine(response.IsSuccessStatusCode
//                     ? "Security event sent successfully"
//                     : $"Failed to send event: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
//             }
//             catch (Exception ex)
//             {
//                 Console.WriteLine($"Error sending event: {ex.Message}");
//             }
//         }

//         public void Dispose() => _client.Dispose();
//     }

//     public class TokenResponse
//     {
//         [JsonProperty("access_token")]
//         public string? AccessToken { get; set; }
//     }
// }



using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
// using Client.Models;
using Newtonsoft.Json;

namespace Client
{
    public class ApiClient
    {
        private readonly HttpClient _client;
        private readonly string _apiBaseUrl;

        public ApiClient(string apiBaseUrl)
        {
            _client = new HttpClient();
            _apiBaseUrl = apiBaseUrl.EndsWith("/") ? apiBaseUrl : apiBaseUrl + "/";
        }

        public async Task<bool> CreateDjangoAccount(UserAccount userAccount)
        {
            try
            {
                var payload = new
                {
                    username = userAccount.Email,
                    email = userAccount.Email,
                    password = userAccount.Password,
                    sid = userAccount.Sid,
                    client_id = userAccount.ClientId,
                    client_secret = userAccount.ClientSecret
                };
                var content = new StringContent(JsonConvert.SerializeObject(payload), Encoding.UTF8, "application/json");
                var response = await _client.PostAsync($"{_apiBaseUrl}create-user/", content);
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Account created: {responseContent}");
                    return true;
                }
                Console.WriteLine($"Failed to create account: {response.StatusCode}");
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
                Console.WriteLine($"Failed to get OAuth token: {response.StatusCode}");
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
                client = new { sid = serverInfo.Sid },
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
                client = new { sid = securityEvent.Sid },
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
            try
            {
                var content = new StringContent(JsonConvert.SerializeObject(payload), Encoding.UTF8, "application/json");
                var request = new HttpRequestMessage(HttpMethod.Post, $"{_apiBaseUrl}api/events/")
                {
                    Content = content
                };
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                var response = await _client.SendAsync(request);
                response.EnsureSuccessStatusCode();
                Console.WriteLine("Security event sent successfully");
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"Failed to send security event: {ex.Message}");
            }
        }

        public async Task SendFirewallStatus(string accessToken, FirewallStatus firewallStatus)
        {
            var payload = new
            {
                client = new { sid = firewallStatus.Sid },
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
                    Console.WriteLine($"Using OAuth token: {accessToken.Substring(0, Math.Min(accessToken.Length, 20))}...");
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


