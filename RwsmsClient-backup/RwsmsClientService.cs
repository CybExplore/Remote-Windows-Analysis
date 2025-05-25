using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace RwsmsClient;

public class RwsmsClientService
{
    private readonly HttpClient _httpClient;
    private readonly CredentialStore _credentials;
    private readonly ILogger<RwsmsClientService> _logger;
    public string AccessToken { get; private set; }
    private string _refreshToken;

    private static readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private const string BaseApiUrl = "http://localhost:8001/";

    public RwsmsClientService(HttpClient httpClient, CredentialStore credentials, ILogger<RwsmsClientService> logger)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = new Uri(BaseApiUrl);
        _credentials = credentials;
        _logger = logger;
    }

    public async Task<bool> RegisterClientAsync(string userEmail)
    {
        try
        {
            var payload = new
            {
                clientId = _credentials.ClientId,
                secretId = _credentials.SecretId,
                sid = _credentials.Sid,
                userEmail
            };
            using var content = new StringContent(JsonSerializer.Serialize(payload, _jsonOptions), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("api/client/register/", content);
            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Client registered successfully.");
                return true;
            }
            _logger.LogError($"Client registration failed: {response.StatusCode} {response.ReasonPhrase}, {await response.Content.ReadAsStringAsync()}");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Client registration error.");
            return false;
        }
    }

    public async Task<bool> AuthenticateAsync()
    {
        try
        {
            var payload = new
            {
                clientId = _credentials.ClientId,
                secretId = _credentials.SecretId,
                sid = _credentials.Sid
            };
            using var content = new StringContent(JsonSerializer.Serialize(payload, _jsonOptions), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("api/client/auth/", content);
            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize<AuthResponse>(await response.Content.ReadAsStringAsync(), _jsonOptions);
                if (result == null || string.IsNullOrWhiteSpace(result.AccessToken))
                {
                    _logger.LogError("Authentication response was invalid.");
                    return false;
                }
                AccessToken = result.AccessToken;
                _refreshToken = result.RefreshToken;
                _logger.LogInformation("Authentication successful.");
                return true;
            }
            _logger.LogError($"Authentication failed: {response.StatusCode} {response.ReasonPhrase}, {await response.Content.ReadAsStringAsync()}");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authentication error.");
            return false;
        }
    }

    public async Task<bool> RefreshTokenAsync()
    {
        try
        {
            var payload = new { refreshToken = _refreshToken };
            using var content = new StringContent(JsonSerializer.Serialize(payload, _jsonOptions), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("api/token/refresh/", content);
            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize<AuthResponse>(await response.Content.ReadAsStringAsync(), _jsonOptions);
                if (result == null || string.IsNullOrWhiteSpace(result.AccessToken))
                {
                    _logger.LogError("Refresh response was invalid.");
                    return false;
                }
                AccessToken = result.AccessToken;
                _refreshToken = result.RefreshToken;
                _logger.LogInformation("Token refreshed successfully.");
                return true;
            }
            _logger.LogError($"Token refresh failed: {response.StatusCode} {response.ReasonPhrase}, {await response.Content.ReadAsStringAsync()}");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token refresh error.");
            return false;
        }
    }

    public async Task SendUserDataAsync()
    {
        try
        {
            var userData = CollectUserData();
            var payload = new { clientId = _credentials.ClientId, userData };
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", AccessToken);

            using var content = new StringContent(JsonSerializer.Serialize(payload, _jsonOptions), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("api/user/profile/", content);
            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("User profile data sent successfully.");
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized && await RefreshTokenAsync())
            {
                _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", AccessToken);
                response = await _httpClient.PostAsync("api/user/profile/", content);
                if (response.IsSuccessStatusCode)
                    _logger.LogInformation("User profile data sent successfully after token refresh.");
            }
            else
            {
                _logger.LogError($"Failed to send user data: {response.StatusCode} {response.ReasonPhrase}, {await response.Content.ReadAsStringAsync()}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending user data.");
        }
    }

    public async Task SendEventLogsAsync()
    {
        try
        {
            var logs = CollectEventLogs();
            if (!logs.Any()) return;

            var payload = new { clientId = _credentials.ClientId, logs };
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", AccessToken);

            using var content = new StringContent(JsonSerializer.Serialize(payload, _jsonOptions), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("api/logs/", content);
            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation($"Sent {logs.Count} event logs.");
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized && await RefreshTokenAsync())
            {
                _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", AccessToken);
                response = await _httpClient.PostAsync("api/logs/", content);
                if (response.IsSuccessStatusCode)
                    _logger.LogInformation($"Sent {logs.Count} event logs after token refresh.");
            }
            else
            {
                _logger.LogError($"Failed to send event logs: {response.StatusCode} {response.ReasonPhrase}, {await response.Content.ReadAsStringAsync()}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending event logs.");
        }
    }

    private object CollectUserData()
    {
        string username = Environment.UserName;
        return new
        {
            accountInfo = GetUserAccountInfo(username),
            groups = GetUserGroups(username),
            profiles = GetUserProfiles(username),
            sessions = GetLoggedOnSessions(username),
            environment = Environment.GetEnvironmentVariables()
        };
    }

    private Dictionary<string, object> GetUserAccountInfo(string username)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\cimv2");
            var query = new ObjectQuery($"SELECT * FROM Win32_UserAccount WHERE Name = '{username}'");
            using var searcher = new ManagementObjectSearcher(scope, query);
            var user = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
            if (user == null) return new();

            return new()
            {
                { "AccountType", user["AccountType"] },
                { "Caption", user["Caption"] },
                { "Description", user["Description"] },
                { "Disabled", user["Disabled"] },
                { "Domain", user["Domain"] },
                { "FullName", user["FullName"] },
                { "InstallDate", user["InstallDate"] },
                { "LocalAccount", user["LocalAccount"] },
                { "Lockout", user["Lockout"] },
                { "Name", user["Name"] },
                { "PasswordChangeable", user["PasswordChangeable"] },
                { "PasswordExpires", user["PasswordExpires"] },
                { "PasswordRequired", user["PasswordRequired"] },
                { "SID", user["SID"] },
                { "SIDType", user["SIDType"] },
                { "Status", user["Status"] }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error collecting user account info.");
            return new();
        }
    }

    private List<string> GetUserGroups(string username)
    {
        try
        {
            var groups = new List<string>();
            var scope = new ManagementScope(@"\\.\root\cimv2");
            var query = new ObjectQuery($"SELECT * FROM Win32_GroupUser WHERE PartComponent LIKE '%Name=\"{username}\"%'");
            using var searcher = new ManagementObjectSearcher(scope, query);
            foreach (var group in searcher.Get())
            {
                string groupComponent = group["GroupComponent"]?.ToString();
                if (!string.IsNullOrEmpty(groupComponent))
                {
                    try
                    {
                        var groupName = groupComponent.Split("Name=\"")[1].Split('"')[0];
                        groups.Add(groupName);
                    }
                    catch { }
                }
            }
            return groups;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error collecting user groups.");
            return new();
        }
    }

    private List<object> GetUserProfiles(string username)
    {
        try
        {
            var profiles = new List<object>();
            var scope = new ManagementScope(@"\\.\root\cimv2");
            var query = new ObjectQuery("SELECT LocalPath, LastUseTime, Status FROM Win32_UserProfile");
            using var searcher = new ManagementObjectSearcher(scope, query);
            foreach (var profile in searcher.Get())
            {
                var localPath = profile["LocalPath"]?.ToString();
                if (!string.IsNullOrEmpty(localPath) && localPath.Contains(username, StringComparison.OrdinalIgnoreCase))
                {
                    profiles.Add(new
                    {
                        LocalPath = localPath,
                        LastUseTime = ConvertWmiDateTime(profile["LastUseTime"]?.ToString()),
                        Status = profile["Status"]?.ToString()
                    });
                }
            }
            return profiles;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error collecting user profiles.");
            return new();
        }
    }

    private List<object> GetLoggedOnSessions(string username)
    {
        try
        {
            var sessions = new List<object>();
            var scope = new ManagementScope(@"\\.\root\cimv2");
            var query = new ObjectQuery("SELECT * FROM Win32_LogonSession");
            using var searcher = new ManagementObjectSearcher(scope, query);
            foreach (var session in searcher.Get())
            {
                var assocQuery = new ObjectQuery($"ASSOCIATORS OF {{Win32_LogonSession.LogonId='{session["LogonId"]}'}} WHERE AssocClass=Win32_LoggedOnUser Role=Dependent");
                using var assocSearcher = new ManagementObjectSearcher(scope, assocQuery);
                foreach (var user in assocSearcher.Get())
                {
                    if (user["Name"]?.ToString().Equals(username, StringComparison.OrdinalIgnoreCase) == true)
                    {
                        sessions.Add(new
                        {
                            LogonId = session["LogonId"]?.ToString(),
                            LogonType = session["LogonType"]?.ToString(),
                            StartTime = ConvertWmiDateTime(session["StartTime"]?.ToString())
                        });
                    }
                }
            }
            return sessions;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error collecting user sessions.");
            return new();
        }
    }

    private List<object> CollectEventLogs()
    {
        try
        {
            var logs = new List<object>();
            string[] logNames = { "Security", "Application", "System" };
            var recentTime = DateTime.UtcNow.AddMinutes(-5);

            foreach (var logName in logNames)
            {
                using var eventLog = new EventLog(logName);
                foreach (EventLogEntry entry in eventLog.Entries.Cast<EventLogEntry>().Where(e => e.TimeGenerated >= recentTime))
                {
                    logs.Add(new
                    {
                        eventType = logName,
                        eventId = entry.EventID,
                        source = entry.Source,
                        timestamp = entry.TimeGenerated.ToUniversalTime().ToString("o"),
                        details = new
                        {
                            message = entry.Message,
                            category = entry.Category,
                            instanceId = entry.InstanceId
                        }
                    });
                }
            }
            return logs;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error collecting event logs.");
            return new();
        }
    }

    private string ConvertWmiDateTime(string wmiDate)
    {
        if (string.IsNullOrWhiteSpace(wmiDate)) return null;
        try
        {
            return DateTime.ParseExact(wmiDate.Split('.')[0], "yyyyMMddHHmmss", null).ToString("o");
        }
        catch
        {
            return wmiDate;
        }
    }
}

public class AuthResponse
{
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
}
