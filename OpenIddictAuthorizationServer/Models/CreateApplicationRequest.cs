using System.ComponentModel.DataAnnotations;

namespace OpenIddictAuthorizationServer.Models;

public class CreateApplicationRequest
{
    [Required]
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    [Required]
    public string DisplayName { get; set; } = string.Empty;
    [Required, Url]
    public string RedirectUri { get; set; } = string.Empty;
    [Required, Url]
    public string PostLogoutRedirectUri { get; set; } = string.Empty;
}
