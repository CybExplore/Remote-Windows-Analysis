// // CredentialManager.cs


// using System.Security.Cryptography;
// using System.Text;

// namespace Client
// {
//     public class CredentialManager
//     {
//         public static string GenerateRandomPassword(int length = 12)
//         {
//             const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()<>"; 
//             byte[] randomBytes = new byte[length];
//             RandomNumberGenerator.Fill(randomBytes);
//             var password = new StringBuilder(length);
//             foreach (byte b in randomBytes)
//             {
//                 password.Append(validChars[b % validChars.Length]);
//             }
//             return password.ToString();
//         }

//         public static string GenerateClientId() => Guid.NewGuid().ToString("N");

//         public static string GenerateClientSecret()
//         {
//             byte[] randomBytes = new byte[32];
//             RandomNumberGenerator.Fill(randomBytes);
//             return Convert.ToBase64String(randomBytes);
//         }

//         public static bool IsValidEmail(string email)
//         {
//             try
//             {
//                 var addr = new System.Net.Mail.MailAddress(email);
//                 return addr.Address == email;
//             }
//             catch
//             {
//                 return false;
//             }
//         }

//         public void SaveCredentials(string sid, string clientId, string clientSecret)
//         {
//             var data = Encoding.UTF8.GetBytes($"{sid}:{clientId}:{clientSecret}");
//             var protectedData = ProtectedData.Protect(data, null, DataProtectionScope.LocalMachine);
//             File.WriteAllBytes("credentials.dat", protectedData);
//             Console.WriteLine("Credentials saved securely to credentials.dat");
//         }

//         public (string? sid, string? clientId, string? clientSecret) LoadCredentials()
//         {
//             if (!File.Exists("credentials.dat"))
//             {
//                 Console.WriteLine("No existing credentials found; proceeding with new account creation");
//                 return (null, null, null);
//             }

//             try
//             {
//                 var protectedData = File.ReadAllBytes("credentials.dat");
//                 var data = ProtectedData.Unprotect(protectedData, null, DataProtectionScope.LocalMachine);
//                 var parts = Encoding.UTF8.GetString(data).Split(':');
//                 if (parts.Length == 3)
//                 {
//                     Console.WriteLine("Loaded credentials from credentials.dat");
//                     return (parts[0], parts[1], parts[2]);
//                 }
//             }
//             catch (Exception ex)
//             {
//                 Console.WriteLine($"Failed to load credentials: {ex.Message}");
//             }
//             return (null, null, null);
//         }
//     }
// }

using System.Security.Cryptography;
using System.Text;

namespace Client
{
    public class CredentialManager
    {
        public static string GenerateRandomPassword(int length = 12)
        {
            const string validChars = "abcdecdfghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()<>"; 
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
            return Convert.ToBase64String(randomBytes);
        }

        public static bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        public void SaveCredentials(string sid, string clientId, string clientSecret)
        {
            var data = Encoding.UTF8.GetBytes($"{sid}:{clientId}:{clientSecret}");
            var protectedData = ProtectedData.Protect(data, null, DataProtectionScope.LocalMachine);
            File.WriteAllBytes("credentials.dat", protectedData);
            Console.WriteLine("Credentials saved securely to credentials.dat");
        }

        public (string? sid, string? clientId, string? clientSecret) LoadCredentials()
        {
            if (!File.Exists("credentials.dat"))
            {
                Console.WriteLine("No existing credentials found; proceeding with new account creation");
                return (null, null, null);
            }

            try
            {
                var protectedData = File.ReadAllBytes("credentials.dat");
                var data = ProtectedData.Unprotect(protectedData, null, DataProtectionScope.LocalMachine);
                var parts = Encoding.UTF8.GetString(data).Split(':');
                if (parts.Length == 3)
                {
                    Console.WriteLine("Loaded credentials from credentials.dat");
                    return (parts[0], parts[1], parts[2]);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to load credentials: {ex.Message}");
            }
            return (null, null, null);
        }
    }
}


