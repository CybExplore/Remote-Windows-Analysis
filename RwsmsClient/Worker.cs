using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Mail;

namespace RwsmsClient;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly RwsmsClientService _clientService;
    private readonly IConfiguration _configuration;
    private readonly int _retryDelaySeconds;
    private bool _isRegistered;
    private readonly string? _userEmail;
    private readonly string _fullName;

    public Worker(
        ILogger<Worker> logger, 
        RwsmsClientService clientService, 
        IConfiguration configuration)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _clientService = clientService ?? throw new ArgumentNullException(nameof(clientService));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        
        _userEmail = configuration.GetValue<string>("WorkerSettings:UserEmail");
        _fullName = configuration.GetValue<string>("WorkerSettings:FullName") ?? "Default User";
        _retryDelaySeconds = configuration.GetValue<int>("WorkerSettings:RetryDelaySeconds", 60);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string? userEmail = _userEmail ?? GetEmailFromConsole();
        if (string.IsNullOrWhiteSpace(userEmail))
        {
            _logger.LogError("Email address is required for registration.");
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (stoppingToken.IsCancellationRequested) return;

                if (!_isRegistered && !await RegisterClientAsync(userEmail, stoppingToken))
                    continue;

                if (string.IsNullOrEmpty(_clientService.AccessToken))
                {
                    if (!await AuthenticateAsync(stoppingToken))
                        continue;
                }

                await SendDataAsync(stoppingToken);
                await Task.Delay(TimeSpan.FromSeconds(_configuration.GetValue<int>("WorkerSettings:PollIntervalSeconds", 5)), stoppingToken);
            }
            catch (TaskCanceledException)
            {
                _logger.LogInformation("Worker stopping.");
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Worker error occurred.");
                await Task.Delay(TimeSpan.FromSeconds(_retryDelaySeconds), stoppingToken);
            }
        }
    }

    private string? GetEmailFromConsole()
    {
        for (int attempts = 0; attempts < 3; attempts++)
        {
            Console.WriteLine("Please enter your email address for registration:");
            string? email = Console.ReadLine()?.Trim();
            if (IsValidEmail(email))
                return email;
            _logger.LogError("Invalid email format. Please try again.");
        }
        _logger.LogError("Failed to get valid email after multiple attempts.");
        return string.Empty;
    }

    private async Task<bool> RegisterClientAsync(string email, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return false;

        _logger.LogInformation("Registering client for email {Email}.", email);
        bool registered = await _clientService.RegisterClientAsync(email, _fullName);
        
        if (!registered)
        {
            _logger.LogError("Registration failed for email {Email}. Retrying in {Delay} seconds.", email, _retryDelaySeconds);
            await Task.Delay(TimeSpan.FromSeconds(_retryDelaySeconds), ct);
            return false;
        }

        _isRegistered = true;
        LaunchFrontend();
        _clientService.SubscribeToEventLogs();
        return true;
    }

    private void LaunchFrontend()
    {
        string frontendUrl = _configuration.GetValue<string>("WorkerSettings:FrontendUrl") ?? "http://localhost:3000/";
        if (!Uri.TryCreate(frontendUrl, UriKind.Absolute, out _))
        {
            _logger.LogError("Invalid FrontendUrl: {Url}", frontendUrl);
            Console.WriteLine($"Invalid frontend URL: {frontendUrl}");
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = frontendUrl,
                UseShellExecute = true
            });
            _logger.LogInformation("Launched frontend at {Url}.", frontendUrl);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to launch browser for {Url}.", frontendUrl);
            Console.WriteLine($"Please visit: {frontendUrl}");
        }
    }

    private async Task<bool> AuthenticateAsync(CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return false;

        _logger.LogInformation("Authenticating...");
        bool authenticated = await _clientService.AuthenticateAsync();
        
        if (!authenticated)
        {
            _logger.LogError("Authentication failed. Retrying in {Delay} seconds.", _retryDelaySeconds);
            await Task.Delay(TimeSpan.FromSeconds(_retryDelaySeconds), ct);
            return false;
        }
        
        return true;
    }

    private async Task SendDataAsync(CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        _logger.LogInformation("Sending user data...");
        await _clientService.SendUserDataAsync();

        _logger.LogInformation("Sending event logs...");
        await _clientService.SendEventLogsAsync();

        _logger.LogInformation("Sending process logs...");
        await _clientService.SendProcessLogsAsync();

        _logger.LogInformation("Sending network logs...");
        await _clientService.SendNetworkLogsAsync();

        _logger.LogInformation("Sending file logs...");
        await _clientService.SendFileLogsAsync();
    }

    private static bool IsValidEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;

        try
        {
            var addr = new MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }
}