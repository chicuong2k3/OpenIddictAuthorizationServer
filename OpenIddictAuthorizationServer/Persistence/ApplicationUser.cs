using Microsoft.AspNetCore.Identity;

namespace OpenIddictAuthorizationServer.Persistence;

public class ApplicationUser : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Picture { get; set; }
}
