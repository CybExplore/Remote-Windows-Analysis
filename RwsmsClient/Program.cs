using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using RwsmsClient;

IHost host = Host.CreateDefaultBuilder(args)
    .ConfigureServices((context, services) =>
    {
        services.AddOptions<WorkerSettings>()
            .Bind(context.Configuration.GetSection("WorkerSettings"))
            .ValidateDataAnnotations();
        services.AddHttpClient<RwsmsClientService>();
        services.AddSingleton<CredentialStore>();
        services.AddHostedService<Worker>();
    })
    .Build();

await host.RunAsync();