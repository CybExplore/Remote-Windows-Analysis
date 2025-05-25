using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Linq;

// namespace RwsmsClient;

public class CredentialStore
{
    private readonly string _credentialFilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "RwsmsClient", "credentials.json");

    public string ClientId { get; private set; } = string.Empty;
    public string SecretId { get; private set; } = string.Empty;
    public string Sid { get; private set; } = string.Empty;

    public CredentialStore()
    {
        if (File.Exists(_credentialFilePath))
        {
            LoadCredentials();
        }
        else
        {
            GenerateCredentials();
            SaveCredentials();
        }
    }

    private void GenerateCredentials()
    {
        ClientId = Guid.NewGuid().ToString();
        SecretId = GenerateRandomString(32);
        Sid = GetUserSid();
    }

    private void LoadCredentials()
    {
        var json = File.ReadAllText(_credentialFilePath);
        var creds = JsonSerializer.Deserialize<Credentials>(json);
        ClientId = creds?.ClientId ?? throw new Exception("ClientId is missing in credentials.");
        SecretId = creds?.SecretId ?? throw new Exception("SecretId is missing in credentials.");
        Sid = creds?.Sid ?? throw new Exception("Sid is missing in credentials.");
    }

    private void SaveCredentials()
    {
        var directory = Path.GetDirectoryName(_credentialFilePath);
        if (directory != null)
        {
            Directory.CreateDirectory(directory);
        }

        var creds = new Credentials { ClientId = ClientId, SecretId = SecretId, Sid = Sid };
        var json = JsonSerializer.Serialize(creds, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_credentialFilePath, json);
    }

    private string GenerateRandomString(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        var result = new char[length];
        for (int i = 0; i < length; i++)
        {
            result[i] = chars[bytes[i] % chars.Length];
        }
        return new string(result);
    }

    private string GetUserSid()
    {
        try
        {
            var scope = new System.Management.ManagementScope(@"\\.\root\cimv2");
            var query = new System.Management.ObjectQuery($"SELECT SID FROM Win32_UserAccount WHERE Name = '{Environment.UserName}'");
            using var searcher = new System.Management.ManagementObjectSearcher(scope, query);
            var user = searcher.Get().Cast<System.Management.ManagementObject>().FirstOrDefault();
            return user?["SID"]?.ToString() ?? throw new Exception("SID not found.");
        }
        catch (Exception ex)
        {
            throw new Exception("Failed to retrieve SID.", ex);
        }
    }

    private class Credentials
    {
        public string? ClientId { get; set; }
        public string? SecretId { get; set; }
        public string? Sid { get; set; }
    }
}
