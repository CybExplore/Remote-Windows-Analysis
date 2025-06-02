using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace RwsmsClient;

public class RwsmsClientService : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly CredentialStore _credentials;
    private readonly ILogger<RwsmsClientService> _logger;
    private readonly IConfiguration _configuration;
    private readonly JsonSerializerOptions _jsonOptions;
    private readonly List<Dictionary<string, object>> _eventLogs;
    private readonly List<EventLogWatcher> _watchers = new();
    private static readonly object _fileLock = new object();
    private string? _accessToken;
    private string? _refreshToken;

    public string AccessToken => _accessToken ?? string.Empty;

    public RwsmsClientService(HttpClient httpClient, CredentialStore credentials, ILogger<RwsmsClientService> logger, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
        _logger = logger;
        _configuration = configuration;
        string? apiBaseUrl = configuration.GetValue<string>("WorkerSettings:ApiBaseUrl");
        if (string.IsNullOrEmpty(apiBaseUrl) || !Uri.TryCreate(apiBaseUrl, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException("ApiBaseUrl is not configured or is invalid.");
        }
        _httpClient.BaseAddress = new Uri(apiBaseUrl);
        _jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        _eventLogs = new List<Dictionary<string, object>>();
    }

    public async Task<bool> RegisterClientAsync(string userEmail, string fullName)
    {
        try
        {
            var payload = new
            {
                client_id = _credentials.ClientId,
                secret_id = _credentials.SecretId,
                sid = _credentials.Sid,
                user_email = userEmail,
                full_name = fullName
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
                client_id = _credentials.ClientId,
                secret_id = _credentials.SecretId,
                sid = _credentials.Sid
            };
            using var content = new StringContent(JsonSerializer.Serialize(payload, _jsonOptions), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("api/client/auth/", content);
            if (response.IsSuccessStatusCode)
            {
                try
                {
                    var authResponse = JsonSerializer.Deserialize<AuthResponse>(await response.Content.ReadAsStringAsync(), _jsonOptions);
                    if (authResponse != null && !string.IsNullOrEmpty(authResponse.AccessToken))
                    {
                        _accessToken = authResponse.AccessToken;
                        _refreshToken = authResponse.RefreshToken;
                        _logger.LogInformation("Authentication successful.");
                        return true;
                    }
                    _logger.LogError("Authentication response is null or missing access token.");
                    return false;
                }
                catch (JsonException ex)
                {
                    _logger.LogError(ex, "Failed to deserialize authentication response.");
                    return false;
                }
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
            var payload = new
            {
                client_id = _credentials.ClientId,
                refresh_token = _refreshToken
            };
            using var content = new StringContent(JsonSerializer.Serialize(payload, _jsonOptions), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("api/client/refresh/", content);
            if (response.IsSuccessStatusCode)
            {
                try
                {
                    var authResponse = JsonSerializer.Deserialize<AuthResponse>(await response.Content.ReadAsStringAsync(), _jsonOptions);
                    if (authResponse != null && !string.IsNullOrEmpty(authResponse.AccessToken))
                    {
                        _accessToken = authResponse.AccessToken;
                        _refreshToken = authResponse.RefreshToken;
                        _logger.LogInformation("Token refreshed successfully.");
                        return true;
                    }
                    _logger.LogError("Token refresh response is null or missing access token.");
                    return false;
                }
                catch (JsonException ex)
                {
                    _logger.LogError(ex, "Failed to deserialize token refresh response.");
                    return false;
                }
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
        string? logFilePath = _configuration.GetValue<string>("WorkerSettings:LogFilePath");
        if (string.IsNullOrEmpty(logFilePath))
        {
            _logger.LogError("LogFilePath is not configured.");
            return;
        }

        try
        {
            if (string.IsNullOrEmpty(_accessToken) && !await RefreshTokenAsync())
            {
                _logger.LogError("Failed to refresh token before sending user data.");
                return;
            }

            var userData = new
            {
                AccountInfo = GetAccountInfo(),
                Groups = GetUserGroups(),
                Profiles = GetUserProfiles(),
                Sessions = GetUserSessions(),
                Environment = GetEnvironmentInfo()
            };
            var payload = new
            {
                client_id = _credentials.ClientId,
                user_data = userData
            };
            using var content = new StringContent(JsonSerializer.Serialize(payload, _jsonOptions), Encoding.UTF8, "application/json");
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            var response = await _httpClient.PostAsync("api/user/profile/", content);
            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("User data sent successfully.");
            }
            else
            {
                _logger.LogError($"Failed to send user data: {response.StatusCode} {response.ReasonPhrase}, {await response.Content.ReadAsStringAsync()}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send user data.");
        }
    }

    public async Task SendEventLogsAsync()
    {
        string? logFilePath = _configuration.GetValue<string>("WorkerSettings:LogFilePath");
        if (string.IsNullOrEmpty(logFilePath))
        {
            _logger.LogError("LogFilePath is not configured.");
            return;
        }

        if (!File.Exists(logFilePath))
        {
            _logger.LogWarning($"Log file {logFilePath} does not exist.");
            return;
        }

        try
        {
            if (string.IsNullOrEmpty(_accessToken) && !await RefreshTokenAsync())
            {
                _logger.LogError("Failed to refresh token before sending event logs.");
                return;
            }

            var json = await File.ReadAllTextAsync(logFilePath);
            var logs = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(json, _jsonOptions);
            if (logs == null || logs.Count == 0)
            {
                _logger.LogInformation("No logs to send.");
                return;
            }

            var payload = new
            {
                client_id = _credentials.ClientId,
                logs
            };
            using var content = new StringContent(JsonSerializer.Serialize(payload, _jsonOptions), Encoding.UTF8, "application/json");
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            var response = await _httpClient.PostAsync("api/logs/", content);
            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation($"Sent {logs.Count} logs to server.");
                await File.WriteAllTextAsync(logFilePath, "[]"); // Clear file
            }
            else
            {
                _logger.LogError($"Failed to send logs: {response.StatusCode} {response.ReasonPhrase}, {await response.Content.ReadAsStringAsync()}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send logs.");
        }
    }

    public void SubscribeToEventLogs()
    {
        string? logFilePath = _configuration.GetValue<string>("WorkerSettings:LogFilePath");
        if (string.IsNullOrEmpty(logFilePath))
        {
            throw new InvalidOperationException("LogFilePath is not configured.");
        }
        int batchSize = _configuration.GetValue<int>("WorkerSettings:BatchSize");
        string[] logNames = _configuration.GetSection("WorkerSettings:LogNames").Get<string[]>() 
            ?? ["System", "Application", "Security"];
        foreach (var logName in logNames)
        {
            try
            {
                var query = new EventLogQuery(logName, PathType.LogName);
                var watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += (sender, e) => HandleEventRecord(e.EventRecord, logFilePath, batchSize);
                watcher.Enabled = true;
                _watchers.Add(watcher);
                _logger.LogInformation($"Subscribed to {logName} log.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to subscribe to {logName} log.");
            }
        }
    }

    private void HandleEventRecord(EventRecord? record, string logFilePath, int batchSize)
    {
        if (record == null) return;

        try
        {
            if (record.TimeCreated == null)
            {
                _logger.LogWarning("Event record {EventId} has no timestamp.", record.Id);
            }

            var logEntry = new Dictionary<string, object>
            {
                { "event_type", record.Id },
                { "event_id", record.Id },
                { "source", record.LogName },
                { "timestamp", record.TimeCreated?.ToString("o") ?? DateTime.UtcNow.ToString("o") },
                { "details", record.FormatDescription() ?? string.Empty }
            };
            lock (_eventLogs)
            {
                _eventLogs.Add(logEntry);
                if (_eventLogs.Count >= batchSize)
                {
                    Task.Run(() => SaveLogsToFileAsync(logFilePath)).GetAwaiter().GetResult();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to handle event record {EventId}.", record.Id);
        }
    }

    private async Task SaveLogsToFileAsync(string logFilePath)
    {
        try
        {
            lock (_fileLock)
            {
                List<Dictionary<string, object>> logsToSave;
                lock (_eventLogs)
                {
                    logsToSave = new List<Dictionary<string, object>>(_eventLogs);
                    _eventLogs.Clear();
                }

                List<Dictionary<string, object>> existingLogs = [];
                if (File.Exists(logFilePath))
                {
                    var json = File.ReadAllText(logFilePath);
                    var deserialized = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(json, _jsonOptions);
                    if (deserialized != null)
                    {
                        existingLogs = deserialized;
                    }
                }

                existingLogs.AddRange(logsToSave);
                var updatedJson = JsonSerializer.Serialize(existingLogs, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(logFilePath, updatedJson);
                _logger.LogInformation($"Saved {logsToSave.Count} logs to {logFilePath}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save logs to file {FilePath}.", logFilePath);
        }
    }

    private Dictionary<string, object> GetAccountInfo()
    {
        try
        {
            return new Dictionary<string, object>
            {
                { "username", Environment.UserName },
                { "domain", Environment.UserDomainName },
                { "sid", _credentials.Sid }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get account info for user {UserName}.", Environment.UserName);
            throw;
        }
    }

    private List<string> GetUserGroups()
    {
        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return identity.Groups?.Select(g => g.Translate(typeof(System.Security.Principal.NTAccount)).Value).ToList() 
                ?? throw new Exception("No groups found for current user.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get user groups for user {UserName}.", Environment.UserName);
            throw;
        }
    }

    private Dictionary<string, object> GetUserProfiles()
    {
        try
        {
            return new Dictionary<string, object>
            {
                { "profile_path", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) },
                { "roaming_profile", Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "ProfileImagePath", "")?.ToString() ?? "" }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get user profiles for user {UserName}.", Environment.UserName);
            throw;
        }
    }

    private List<Dictionary<string, object>> GetUserSessions()
    {
        try
        {
            return [
                new Dictionary<string, object>
                {
                    { "session_id", Process.GetCurrentProcess().SessionId },
                    { "start_time", DateTime.Now.ToString("o") }
                }
            ];
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get user sessions for user {UserName}.", Environment.UserName);
            throw;
        }
    }

    private Dictionary<string, object> GetEnvironmentInfo()
    {
        try
        {
            return new Dictionary<string, object>
            {
                { "os_version", Environment.OSVersion.VersionString },
                { "machine_name", Environment.MachineName },
                { "processor_count", Environment.ProcessorCount }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get environment info for machine {MachineName}.", Environment.MachineName);
            throw;
        }
    }

    public void Dispose()
    {
        foreach (var watcher in _watchers)
        {
            watcher.Dispose();
        }
    }

    private class AuthResponse
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
    }
}