// // Models/UserAccount.cs

// using Newtonsoft.Json;

// namespace Client
// {
//     public class UserAccount
//     {
//         [JsonProperty("sid")] public string? Sid { get; set; }
//         [JsonProperty("email")] public string? Email { get; set; }
//         [JsonProperty("password")] public string? Password { get; set; }
//         [JsonProperty("full_name")] public string? FullName { get; set; }
//         [JsonProperty("domain")] public string? Domain { get; set; }
//         [JsonProperty("account_type")] public string? AccountType { get; set; }
//         [JsonProperty("caption")] public string? Caption { get; set; }
//         [JsonProperty("sid_type")] public string? SidType { get; set; }
//         [JsonProperty("description")] public string? Description { get; set; }
//         [JsonProperty("status")] public string? Status { get; set; }
//         [JsonProperty("local_account")] public bool LocalAccount { get; set; }
//         [JsonProperty("is_shutting_down")] public bool IsShuttingDown { get; set; }
//         [JsonProperty("client_id")] public string? ClientId { get; set; }
//         [JsonProperty("client_secret")] public string? ClientSecret { get; set; }
//         [JsonProperty("profile")] public object Profile => new { Description };
//     }
// }


using Newtonsoft.Json;

namespace Client
{
    public class UserAccount
    {
        [JsonProperty("sid")] public string? Sid { get; set; }
        [JsonProperty("email")] public string? Email { get; set; }
        [JsonProperty("password")] public string? Password { get; set; }
        [JsonProperty("full_name")] public string? FullName { get; set; }
        [JsonProperty("domain")] public string? Domain { get; set; }
        [JsonProperty("account_type")] public string? AccountType { get; set; }
        [JsonProperty("caption")] public string? Caption { get; set; }
        [JsonProperty("sid_type")] public string? SidType { get; set; }
        [JsonProperty("description")] public string? Description { get; set; }
        [JsonProperty("status")] public string? Status { get; set; }
        [JsonProperty("local_account")] public bool LocalAccount { get; set; }
        [JsonProperty("is_shutting_down")] public bool IsShuttingDown { get; set; }
        [JsonProperty("client_id")] public string? ClientId { get; set; }
        [JsonProperty("client_secret")] public string? ClientSecret { get; set; }
        [JsonProperty("profile")] public object Profile => new { Description };
    }
}

