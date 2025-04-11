// Models/UserAccount.cs

namespace Client
{
    public class UserAccount
    {
        public string? Sid { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
        public string? FullName { get; set; }
        public string? Domain { get; set; }
        public string? AccountType { get; set; }
        public string? Caption { get; set; }
        public string? SidType { get; set; }
        public string? Description { get; set; }
        public string? Status { get; set; }
        public bool LocalAccount { get; set; }
        public bool IsShuttingDown { get; set; }
        public string? ClientId { get; set; }
        public string? ClientSecret { get; set; }
        public object Profile => new { Description };
    }
}

