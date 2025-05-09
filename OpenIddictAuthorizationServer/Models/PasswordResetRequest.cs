using System.ComponentModel.DataAnnotations;

namespace OpenIddictAuthorizationServer.Models;

public class PasswordResetRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}
