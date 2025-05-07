using Microsoft.AspNetCore.Identity;

namespace OpenIddictAuthorizationServer.Persistence;

public class ApplicationUser : IdentityUser
{
    public string? Picture { get; set; }
}
