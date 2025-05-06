using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Client
{
    public class CredentialManager
    {
        public static string GenerateRandomPassword(int length = 16)
        {
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()<>?";
            byte[] randomBytes = new byte[length];
            RandomNumberGenerator.Fill(randomBytes);
            var password = new StringBuilder(length);
            foreach (byte b in randomBytes)
            {
                password.Append(validChars[b % validChars.Length]);
            }
            return password.ToString();
        }

        public static string GenerateClientId() => Guid.NewGuid().ToString("N");

        public static string GenerateClientSecret()
        {
            byte[] randomBytes = new byte[32];
            RandomNumberGenerator.Fill(randomBytes);
            return Convert.ToBase64String(randomBytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        }

        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email && !email.Contains("temporary") && !email.Contains("disposable");
            }
            catch
            {
                return false;
            }
        }

        public void SaveCredentials(string sid, string clientId, string clientSecret, string password)
        {
            try
            {
                var data = Encoding.UTF8.GetBytes($"{sid}:{clientId}:{clientSecret}:{password}");
                var protectedData = ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes("credentials.dat", protectedData);
                Console.WriteLine("Credentials saved securely to credentials.dat");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to save credentials: {ex.Message}");
                throw;
            }
        }

        public (string? sid, string? clientId, string? clientSecret, string? password) LoadCredentials()
        {
            if (!File.Exists("credentials.dat"))
            {
                Console.WriteLine("No existing credentials found; proceeding with new account creation");
                return (null, null, null, null);
            }

            try
            {
                var protectedData = File.ReadAllBytes("credentials.dat");
                var data = ProtectedData.Unprotect(protectedData, null, DataProtectionScope.CurrentUser);
                var parts = Encoding.UTF8.GetString(data).Split(':');
                if (parts.Length == 4)
                {
                    Console.WriteLine("Loaded credentials from credentials.dat");
                    return (parts[0], parts[1], parts[2], parts[3]);
                }
                Console.WriteLine("Invalid credential format");
                return (null, null, null, null);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to load credentials: {ex.Message}");
                return (null, null, null, null);
            }
        }
    }
}
