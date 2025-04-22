// // Worker.cs


// using Microsoft.Extensions.Configuration;
// using Microsoft.Extensions.Hosting;
// using Microsoft.Extensions.Logging;

// namespace Client
// {
//     public class Worker : BackgroundService
//     {
//         private readonly ILogger<Worker> _logger;
//         private readonly CredentialManager _credentialManager;
//         private readonly SystemInfoCollector _systemInfoCollector;
//         private readonly ApiClient _apiClient;
//         private readonly EventMonitor _eventMonitor;
//         private readonly IConfiguration _configuration;

//         public Worker(
//             ILogger<Worker> logger,
//             CredentialManager credentialManager,
//             SystemInfoCollector systemInfoCollector,
//             ApiClient apiClient,
//             EventMonitor eventMonitor,
//             IConfiguration configuration)
//         {
//             _logger = logger;
//             _credentialManager = credentialManager;
//             _systemInfoCollector = systemInfoCollector;
//             _apiClient = apiClient;
//             _eventMonitor = eventMonitor;
//             _configuration = configuration;
//         }

//         protected override async Task ExecuteAsync(CancellationToken stoppingToken)
//         {
//             _logger.LogInformation(1000, "Remote Windows Security Monitoring Service started at {Time}", DateTime.Now);

//             var (sid, clientId, clientSecret) = _credentialManager.LoadCredentials();
//             bool isNewAccount = sid == null;

//             if (isNewAccount)
//             {
//                 string? email = _configuration["ApiSettings:DefaultEmail"];
//                 if (string.IsNullOrEmpty(email) || !CredentialManager.IsValidEmail(email))
//                 {
//                     _logger.LogError(1001, "No valid email provided in configuration for new account creation.");
//                     return;
//                 }

//                 var userAccount = _systemInfoCollector.GetUserAccountInfo();
//                 if (userAccount == null || string.IsNullOrEmpty(userAccount.Sid))
//                 {
//                     _logger.LogError(1002, "Failed to retrieve user account info or SID is empty.");
//                     return;
//                 }

//                 userAccount.Email = email;
//                 userAccount.Password = CredentialManager.GenerateRandomPassword();
//                 userAccount.ClientId = CredentialManager.GenerateClientId();
//                 userAccount.ClientSecret = CredentialManager.GenerateClientSecret();

//                 bool success = await _apiClient.CreateDjangoAccount(userAccount);
//                 if (success)
//                 {
//                     _logger.LogInformation(1003, "Account created successfully. SID: {Sid}, ClientId: {ClientId}", userAccount.Sid, userAccount.ClientId);
//                     _credentialManager.SaveCredentials(userAccount.Sid, userAccount.ClientId, userAccount.ClientSecret);
//                     sid = userAccount.Sid;
//                     clientId = userAccount.ClientId;
//                     clientSecret = userAccount.ClientSecret;
//                 }
//                 else
//                 {
//                     _logger.LogError(1004, "Failed to create account.");
//                     return;
//                 }
//             }
//             else
//             {
//                 _logger.LogInformation(1005, "Existing account found. SID: {Sid}", sid);
//             }

//             string? accessToken = null;
//             if (clientId != null && clientSecret != null)
//             {
//                 accessToken = await _apiClient.GetOAuthTokenWithClientCredentials(clientId, clientSecret);
//             }
//             else
//             {
//                 _logger.LogError(1006, "Client ID or Client Secret is null; cannot obtain OAuth token.");
//             }

//             if (!string.IsNullOrEmpty(accessToken))
//             {
//                 _logger.LogInformation(1007, "OAuth2 token obtained successfully.");
//                 if (sid != null)
//                 {
//                     var serverInfo = _systemInfoCollector.GetServerInfo(sid);
//                     await _apiClient.SendServerInfo(accessToken, serverInfo);
//                     _eventMonitor.Start(sid, accessToken);
//                 }
//                 else
//                 {
//                     _logger.LogError(1008, "SID is null; cannot send server info.");
//                 }
//             }
//             else
//             {
//                 _logger.LogError(1009, "Failed to obtain OAuth2 token.");
//             }

//             _logger.LogInformation(1010, "Monitoring started for SID: {Sid}", sid);

//             while (!stoppingToken.IsCancellationRequested)
//             {
//                 _logger.LogDebug("Service running at {Time}", DateTime.Now);
//                 await Task.Delay(60000, stoppingToken); // Log every minute
//             }
//         }
//     }
// }


using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Client
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly CredentialManager _credentialManager;
        private readonly SystemInfoCollector _systemInfoCollector;
        private readonly ApiClient _apiClient;
        private readonly EventMonitor _eventMonitor;
        private readonly IConfiguration _configuration;

        public Worker(
            ILogger<Worker> logger,
            CredentialManager credentialManager,
            SystemInfoCollector systemInfoCollector,
            ApiClient apiClient,
            EventMonitor eventMonitor,
            IConfiguration configuration)
        {
            _logger = logger;
            _credentialManager = credentialManager;
            _systemInfoCollector = systemInfoCollector;
            _apiClient = apiClient;
            _eventMonitor = eventMonitor;
            _configuration = configuration;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation(1000, "Remote Windows Security Monitoring Service started at {Time}", DateTime.Now);

            var (sid, clientId, clientSecret) = _credentialManager.LoadCredentials();
            bool isNewAccount = sid == null;

            if (isNewAccount)
            {
                string? email = _configuration["ApiSettings:DefaultEmail"];
                if (string.IsNullOrEmpty(email) || !CredentialManager.IsValidEmail(email))
                {
                    _logger.LogError(1001, "No valid email provided in configuration for new account creation.");
                    return;
                }

                var userAccount = _systemInfoCollector.GetUserAccountInfo();
                if (userAccount == null || string.IsNullOrEmpty(userAccount.Sid))
                {
                    _logger.LogError(1002, "Failed to retrieve user account info or SID is empty.");
                    return;
                }

                userAccount.Email = email;
                userAccount.Password = CredentialManager.GenerateRandomPassword();
                userAccount.ClientId = CredentialManager.GenerateClientId();
                userAccount.ClientSecret = CredentialManager.GenerateClientSecret();

                bool success = await _apiClient.CreateDjangoAccount(userAccount);
                if (success)
                {
                    _logger.LogInformation(1003, "Account created successfully. SID: {Sid}, ClientId: {ClientId}", userAccount.Sid, userAccount.ClientId);
                    _credentialManager.SaveCredentials(userAccount.Sid, userAccount.ClientId, userAccount.ClientSecret);
                    sid = userAccount.Sid;
                    clientId = userAccount.ClientId;
                    clientSecret = userAccount.ClientSecret;
                }
                else
                {
                    _logger.LogError(1004, "Failed to create account.");
                    return;
                }
            }
            else
            {
                _logger.LogInformation(1005, "Existing account found. SID: {Sid}", sid);
            }

            string? accessToken = null;
            if (clientId != null && clientSecret != null)
            {
                accessToken = await _apiClient.GetOAuthTokenWithClientCredentials(clientId, clientSecret);
            }
            else
            {
                _logger.LogError(1006, "Client ID or Client Secret is null; cannot obtain OAuth token.");
            }

            if (!string.IsNullOrEmpty(accessToken))
            {
                _logger.LogInformation(1007, "OAuth2 token obtained successfully.");
                if (sid != null)
                {
                    var serverInfo = _systemInfoCollector.GetServerInfo(sid);
                    try
                    {
                        // Temporarily disabled to focus on event monitoring
                        // await _apiClient.SendServerInfo(accessToken, serverInfo);
                        _logger.LogInformation(1011, "Server info sending skipped to debug event monitoring.");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(1011, "Failed to send server info: {Error}", ex.Message);
                    }

                    try
                    {
                        _eventMonitor.Start(sid, accessToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(1012, "Failed to start event monitoring: {Error}. Ensure the application has permissions to access the Security Event Log.", ex.Message);
                    }
                }
                else
                {
                    _logger.LogError(1008, "SID is null; cannot send server info or start monitoring.");
                }
            }
            else
            {
                _logger.LogError(1009, "Failed to obtain OAuth2 token.");
            }

            _logger.LogInformation(1010, "Monitoring started for SID: {Sid}", sid);

            while (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogDebug("Service running at {Time}", DateTime.Now);
                await Task.Delay(60000, stoppingToken);
            }
        }
    }
}

