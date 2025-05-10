using OpenIddictAuthorizationServer.Persistence;

namespace OpenIddictAuthorizationServer.Api.Dtos;

public class ClaimTypeDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsReserved { get; set; }
}

public static class ClaimTypeExtensions
{
    public static ClaimTypeDto MapToDto(this ClaimType claimType)
    {
        return new ClaimTypeDto
        {
            Id = claimType.Id,
            Name = claimType.Name,
            Description = claimType.Description,
            IsReserved = claimType.IsReserved
        };
    }
}