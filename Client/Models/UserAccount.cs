namespace Client.Models
{
    public class UserAccount
    {
        public string Sid { get; set; } = string.Empty;
        public string? Email { get; set; }
        public string? FullName { get; set; }
        public string? Password { get; set; }
        public string? MachineName { get; set; }
        public string? ClientId { get; set; } // Restored for OAuth2
        public string? ClientSecret { get; set; } // Restored for OAuth2
    }
}