using Microsoft.AspNetCore.Identity;
using OpenIddictAuthorizationServer.Persistence;

namespace OpenIddictAuthorizationServer.Api.Dtos;

public class UserDto
{
    public string Id { get; set; } = string.Empty;
    public string? Email { get; set; }
    public string? UserName { get; set; }
    public string? PhoneNumber { get; set; }
    public string? Picture { get; set; }
    public IList<string> Roles { get; set; } = new List<string>();

}

public static class UserExtensions
{
    public static async Task<UserDto> MapToDtoAsync(this ApplicationUser user, UserManager<ApplicationUser> userManager)
    {
        var roles = await userManager.GetRolesAsync(user);

        return new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            UserName = user.UserName,
            PhoneNumber = user.PhoneNumber,
            Picture = user.Picture,
            Roles = roles
        };
    }
}