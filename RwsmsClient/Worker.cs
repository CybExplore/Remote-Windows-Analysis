using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

// namespace RwsmsClient;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly RwsmsClientService _clientService;
    private bool _isRegistered;

    public Worker(ILogger<Worker> logger, RwsmsClientService clientService)
    {
        _logger = logger;
        _clientService = clientService;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Register client if not already registered
                if (!_isRegistered)
                {
                    _logger.LogInformation("Registering client with server...");
                    bool registered = await _clientService.RegisterClientAsync("test@example.com"); // Replace with user email
                    if (!registered)
                    {
                        _logger.LogError("Client registration failed. Retrying in 60 seconds.");
                        await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);
                        continue;
                    }
                    _isRegistered = true;
                }

                // Authenticate
                if (string.IsNullOrEmpty(_clientService.AccessToken))
                {
                    _logger.LogInformation("Authenticating with server...");
                    bool authenticated = await _clientService.AuthenticateAsync();
                    if (!authenticated)
                    {
                        _logger.LogError("Authentication failed. Retrying in 60 seconds.");
                        await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);
                        continue;
                    }
                }

                // Send user profile data
                _logger.LogInformation("Sending user profile data...");
                await _clientService.SendUserDataAsync();

                // Send event logs
                _logger.LogInformation("Sending event logs...");
                await _clientService.SendEventLogsAsync();

                // Wait before next iteration
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in worker execution.");
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
        }
    }
}

