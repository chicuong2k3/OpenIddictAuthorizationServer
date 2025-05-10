namespace OpenIddictAuthorizationServer.Api.Requests;

public class CreateUpdateApplicationRequest
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientType { get; set; } = "web";
    public string? ClientSecret { get; set; }
    public string? DisplayName { get; set; }
    public List<string> RedirectUris { get; set; } = [];
    public List<string> PostLogoutRedirectUris { get; set; } = [];
    public List<string>? Permissions { get; set; }
}
