// ApiClient.cs

using System;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Client
{
    public class ApiClient : IDisposable
    {
        private readonly HttpClient _client;
        private readonly string _apiBaseUrl;

        public ApiClient(string apiBaseUrl)
        {
            _apiBaseUrl = apiBaseUrl;
            _client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        }

        // public async Task<bool> CreateDjangoAccount(UserAccount account)
        // {
        //     var json = Newtonsoft.Json.JsonConvert.SerializeObject(account);
        //     Console.WriteLine("Payload: " + json);

        //     var content = new StringContent(json, Encoding.UTF8, "application/json");
        //     try
        //     {
        //         var response = await _client.PostAsync($"{_apiBaseUrl}/api/create-user/", content);

        //         Console.WriteLine($"\n{response} \n");
        //         if (response.IsSuccessStatusCode)
        //         {
        //             Console.WriteLine("Account created: " + await response.Content.ReadAsStringAsync());
        //             return true;
        //         }
        //         Console.WriteLine($"Error creating account: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
        //         return false;
        //     }
        //     catch (Exception ex)
        //     {
        //         Console.WriteLine($"Error sending request: {ex.Message}");
        //         return false;
        //     }
        // }

        public async Task<bool> CreateDjangoAccount(UserAccount account)
        {
            var json = JsonConvert.SerializeObject(account, new JsonSerializerSettings
            {
                ContractResolver = new Newtonsoft.Json.Serialization.DefaultContractResolver
                {
                    NamingStrategy = new Newtonsoft.Json.Serialization.SnakeCaseNamingStrategy()
                }
            });

            Console.WriteLine("Payload: " + json);

            var content = new StringContent(json, Encoding.UTF8, "application/json");
            try
            {
                var response = await _client.PostAsync($"{_apiBaseUrl}/api/create-user/", content);

                Console.WriteLine($"\n{response} \n");
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine("Account created: " + await response.Content.ReadAsStringAsync());
                    return true;
                }

                Console.WriteLine($"Error creating account: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending request: {ex.Message}");
                return false;
            }
        }

        public static void LaunchBrowser(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to launch browser: {ex.Message}");
            }
        }

        public async Task<string?> GetOAuthTokenWithClientCredentials(string clientId, string clientSecret)
        {
            var payload = new Dictionary<string, string>
            {
                {"grant_type", "client_credentials"},
                {"client_id", clientId},
                {"client_secret", clientSecret}
            };
            try
            {
                var response = await _client.PostAsync($"{_apiBaseUrl}/o/token/", new FormUrlEncodedContent(payload));
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    if (json != null)
                    {
                        dynamic data = Newtonsoft.Json.JsonConvert.DeserializeObject(json);
                        return data?.access_token?.ToString();
                    }
                    Console.WriteLine("Token response was null.");
                    return null;
                }
                Console.WriteLine($"Token request failed: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting token: {ex.Message}");
                return null;
            }
        }

        public async Task SendServerInfo(string accessToken, ServerInfo serverInfo)
        {
            var json = Newtonsoft.Json.JsonConvert.SerializeObject(serverInfo);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            _client.DefaultRequestHeaders.Authorization = new("Bearer", accessToken);
            try
            {
                var response = await _client.PostAsync($"{_apiBaseUrl}/api/server-info/", content);
                Console.WriteLine(response.IsSuccessStatusCode
                    ? "Server info sent successfully"
                    : $"Failed to send server info: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending server info: {ex.Message}");
            }
        }

        public async Task SendSecurityEvent(string accessToken, SecurityEvent securityEvent)
        {
            var json = Newtonsoft.Json.JsonConvert.SerializeObject(securityEvent);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            _client.DefaultRequestHeaders.Authorization = new("Bearer", accessToken);
            try
            {
                var response = await _client.PostAsync($"{_apiBaseUrl}/api/events/", content);
                Console.WriteLine(response.IsSuccessStatusCode
                    ? "Security event sent successfully"
                    : $"Failed to send event: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending event: {ex.Message}");
            }
        }

        public void Dispose() => _client.Dispose();
    }
}
