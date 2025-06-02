using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Net.NetworkInformation;
using System.Security.Principal;
using RwsmsClient.Models;

namespace RwsmsClient;

public class RwsmsClientService : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly CredentialStore _credentials;
    private readonly ILogger<RwsmsClientService> _logger;
    private readonly IConfiguration _configuration;
    private readonly JsonSerializerOptions _jsonOptions;
    private readonly List<SecurityEvent> _eventLogs;
    private readonly List<ProcessLog> _processLogs;
    private readonly List<NetworkLog> _networkLogs;
    private readonly List<FileLog> _fileLogs;
    private readonly List<EventLogWatcher> _watchers;
    private readonly FileSystemWatcher _fileWatcher;
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
        _eventLogs = [];
        _processLogs = [];
        _networkLogs = [];
        _fileLogs = [];
        _watchers = [];

        string monitorPath = configuration.GetValue<string>("WorkerSettings:MonitorPath") ?? @"C:\Windows\System32";
        _fileWatcher = new FileSystemWatcher(monitorPath)
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
            EnableRaisingEvents = true
        };
        _fileWatcher.Changed += (s, e) => HandleFileChange(e);
        _fileWatcher.Created += (s, e) => HandleFileChange(e);
        _fileWatcher.Deleted += (s, e) => HandleFileChange(e);
        _fileWatcher.Renamed += (s, e) => HandleFileRename(e);
        _logger.LogInformation($"Subscribed to file system changes in {monitorPath}.");
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
                account_info = GetAccountInfo(),
                groups = GetUserGroups(),
                profiles = GetUserProfiles(),
                sessions = GetUserSessions(),
                environment = GetEnvironmentInfo()
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

        try
        {
            if (string.IsNullOrEmpty(_accessToken) && !await RefreshTokenAsync())
            {
                _logger.LogError("Failed to refresh token before sending event logs.");
                return;
            }

            List<SecurityEvent> logs;
            lock (_eventLogs)
            {
                logs = new List<SecurityEvent>(_eventLogs);
                _eventLogs.Clear();
            }

            if (logs.Count == 0)
            {
                _logger.LogInformation("No event logs to send.");
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
                _logger.LogInformation($"Sent {logs.Count} event logs to server.");
            }
            else
            {
                _logger.LogError($"Failed to send event logs: {response.StatusCode} {response.ReasonPhrase}, {await response.Content.ReadAsStringAsync()}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send event logs.");
        }
    }

    public async Task SendProcessLogsAsync()
    {
        try
        {
            if (string.IsNullOrEmpty(_accessToken) && !await RefreshTokenAsync())
            {
                _logger.LogError("Failed to refresh token before sending process logs.");
                return;
            }

            var logs = GetRunningProcesses();
            if (logs.Count == 0)
            {
                _logger.LogInformation("No process logs to send.");
                return;
            }

            var payload = new
            {
                client_id = _credentials.ClientId,
                logs
            };
            using var content = new StringContent(JsonSerializer.Serialize(payload, _jsonOptions), Encoding.UTF8, "application/json");
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            var response = await _httpClient.PostAsync("api/processes/", content);
            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation($"Sent {logs.Count} process logs to server.");
                lock (_processLogs) { _processLogs.Clear(); }
            }
            else
            {
                _logger.LogError($"Failed to send process logs: {response.StatusCode} {response.ReasonPhrase}, {await response.Content.ReadAsStringAsync()}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send process logs.");
        }
    }

    public async Task SendNetworkLogsAsync()
    {
        try
        {
            if (string.IsNullOrEmpty(_accessToken) && !await RefreshTokenAsync())
            {
                _logger.LogError("Failed to refresh token before sending network logs.");
                return;
            }

            var logs = GetNetworkConnections();
            if (logs.Count == 0)
            {
                _logger.LogInformation("No network logs to send.");
                return;
            }

            var payload = new
            {
                client_id = _credentials.ClientId,
                logs
            };
            using var content = new StringContent(JsonSerializer.Serialize(payload, _jsonOptions), Encoding.UTF8, "application/json");
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            var response = await _httpClient.PostAsync("api/network/", content);
            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation($"Sent {logs.Count} network logs to server.");
                lock (_networkLogs) { _networkLogs.Clear(); }
            }
            else
            {
                _logger.LogError($"Failed to send network logs: {response.StatusCode} {response.ReasonPhrase}, {await response.Content.ReadAsStringAsync()}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send network logs.");
        }
    }

    public async Task SendFileLogsAsync()
    {
        try
        {
            if (string.IsNullOrEmpty(_accessToken) && !await RefreshTokenAsync())
            {
                _logger.LogError("Failed to refresh token before sending file logs.");
                return;
            }

            List<FileLog> logs;
            lock (_fileLogs)
            {
                logs = new List<FileLog>(_fileLogs);
                _fileLogs.Clear();
            }

            if (logs.Count == 0)
            {
                _logger.LogInformation("No file logs to send.");
                return;
            }

            var payload = new
            {
                client_id = _credentials.ClientId,
                logs
            };
            using var content = new StringContent(JsonSerializer.Serialize(payload, _jsonOptions), Encoding.UTF8, "application/json");
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            var response = await _httpClient.PostAsync("api/files/", content);
            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation($"Sent {logs.Count} file logs to server.");
            }
            else
            {
                _logger.LogError($"Failed to send file logs: {response.StatusCode} {response.ReasonPhrase}, {await response.Content.ReadAsStringAsync()}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send file logs.");
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
        string[] logNames = _configuration.GetSection("WorkerSettings:LogNames").Get<string[]>() ?? ["System", "Application", "Security"];
        foreach (var logName in logNames)
        {
            try
            {
                var query = new EventLogQuery(logName, PathType.LogName, "EventID=4624 or EventID=4625 or EventID=4672");
                var watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += (sender, e) => HandleEventRecord(e.EventRecord, batchSize);
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

    private void HandleEventRecord(EventRecord? record, int batchSize)
    {
        if (record == null) return;

        try
        {
            if (record.TimeCreated == null)
            {
                _logger.LogWarning("Event record {EventId} has no timestamp.", record.Id);
            }

            var logEntry = new SecurityEvent
            {
                EventType = record.Id.ToString(),
                EventId = record.Id,
                Source = record.LogName ?? string.Empty,
                Timestamp = record.TimeCreated?.ToString("o") ?? DateTime.UtcNow.ToString("o"),
                Details = record.FormatDescription() ?? string.Empty
            };
            lock (_eventLogs)
            {
                _eventLogs.Add(logEntry);
                if (_eventLogs.Count >= batchSize)
                {
                    Task.Run(SendEventLogsAsync).GetAwaiter().GetResult();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to handle event record {EventId}.", record.Id);
        }
    }

    private void HandleFileChange(FileSystemEventArgs e)
    {
        try
        {
            var logEntry = new FileLog
            {
                EventType = "FileChange",
                Path = e.FullPath,
                ChangeType = e.ChangeType.ToString(),
                OldPath = string.Empty,
                Timestamp = DateTime.UtcNow.ToString("o")
            };
            lock (_fileLogs)
            {
                _fileLogs.Add(logEntry);
                int batchSize = _configuration.GetValue<int>("WorkerSettings:BatchSize");
                if (_fileLogs.Count >= batchSize)
                {
                    Task.Run(SendFileLogsAsync).GetAwaiter().GetResult();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to handle file change event for {Path}.", e.FullPath);
        }
    }

    private void HandleFileRename(RenamedEventArgs e)
    {
        try
        {
            var logEntry = new FileLog
            {
                EventType = "FileRename",
                Path = e.FullPath,
                ChangeType = e.ChangeType.ToString(),
                OldPath = e.OldFullPath,
                Timestamp = DateTime.UtcNow.ToString("o")
            };
            lock (_fileLogs)
            {
                _fileLogs.Add(logEntry);
                int batchSize = _configuration.GetValue<int>("WorkerSettings:BatchSize");
                if (_fileLogs.Count >= batchSize)
                {
                    Task.Run(SendFileLogsAsync).GetAwaiter().GetResult();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to handle file rename event for {Path}.", e.OldFullPath);
        }
    }

    private List<ProcessLog> GetRunningProcesses()
    {
        try
        {
            var processes = Process.GetProcesses();
            var logs = processes.Select(p => new ProcessLog
            {
                Name = p.ProcessName,
                Pid = p.Id,
                Path = p.MainModule?.FileName ?? "N/A",
                StartTime = p.StartTime.ToString("o")
            }).ToList();
            lock (_processLogs)
            {
                _processLogs.AddRange(logs);
            }
            return logs;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get running processes.");
            return [];
        }
    }

    private List<NetworkLog> GetNetworkConnections()
    {
        try
        {
            var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            var logs = connections.Select(c => new NetworkLog
            {
                LocalAddress = c.LocalEndPoint.ToString(),
                RemoteAddress = c.RemoteEndPoint.ToString(),
                State = c.State.ToString(),
                Timestamp = DateTime.UtcNow.ToString("o")
            }).ToList();
            lock (_networkLogs)
            {
                _networkLogs.AddRange(logs);
            }
            return logs;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get network connections.");
            return [];
        }
    }

    private UserAccount GetAccountInfo()
    {
        try
        {
            return new UserAccount
            {
                Username = Environment.UserName,
                Domain = Environment.UserDomainName,
                Sid = _credentials.Sid
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get account info for user {UserName}.", Environment.UserName);
            throw;
        }
    }

    private UserGroup GetUserGroups()
    {
        try
        {
            var identity = WindowsIdentity.GetCurrent();
            var groups = identity.Groups?.Select(g => g.Translate(typeof(NTAccount)).Value).ToList()
                ?? throw new Exception("No groups found for current user.");
            return new UserGroup { Groups = groups };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get user groups for user {UserName}.", Environment.UserName);
            throw;
        }
    }

    private UserProfile GetUserProfiles()
    {
        try
        {
            return new UserProfile
            {
                ProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                RoamingProfile = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "ProfileImagePath", "")?.ToString() ?? ""
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get user profiles for user {UserName}.", Environment.UserName);
            throw;
        }
    }

    private List<UserSession> GetUserSessions()
    {
        try
        {
            return [
                new UserSession
                {
                    SessionId = Process.GetCurrentProcess().SessionId,
                    StartTime = DateTime.Now.ToString("o")
                }
            ];
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get user sessions for user {UserName}.", Environment.UserName);
            throw;
        }
    }

    private EnvironmentInfo GetEnvironmentInfo()
    {
        try
        {
            return new EnvironmentInfo
            {
                OsVersion = Environment.OSVersion.VersionString,
                MachineName = Environment.MachineName,
                ProcessorCount = Environment.ProcessorCount
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
        _fileWatcher?.Dispose();
    }

    private class AuthResponse
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
    }
}
