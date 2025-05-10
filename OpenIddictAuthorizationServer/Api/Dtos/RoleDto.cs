using Microsoft.AspNetCore.Identity;

namespace OpenIddictAuthorizationServer.Api.Dtos;

public class RoleDto
{
    public string Id { get; set; } = string.Empty;
    public string? Name { get; set; }
    public string? NormalizedName { get; set; }
}

public static class RoleExtensions
{
    public static RoleDto MapToDto(this IdentityRole role)
    {
        return new RoleDto
        {
            Id = role.Id,
            Name = role.Name,
            NormalizedName = role.NormalizedName
        };
    }
}
