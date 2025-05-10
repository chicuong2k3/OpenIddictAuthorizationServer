using OpenIddict.EntityFrameworkCore.Models;
using System.Text.Json;

namespace OpenIddictAuthorizationServer.Api.Dtos;

public class ScopeDto
{
    public string? Id { get; set; }
    public string? Name { get; set; }
    public string? Description { get; set; }
    public string? DisplayName { get; set; }
    public List<string> Resources { get; set; } = [];
    public List<string> Claims { get; set; } = [];
}

public static class ScopeDtoExtensions
{
    public static ScopeDto MapToScopeDto(this object scopeObj)
    {
        if (scopeObj is OpenIddictEntityFrameworkCoreScope scope)
        {
            List<string> claims = [];
            if (scope.Properties != null)
            {
                var properties = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(scope.Properties);
                if (properties != null && properties.TryGetValue(Constants.ScopeClaimsKey, out var claimsElement))
                {
                    claims = claimsElement.Deserialize<List<string>>() ?? [];
                }
            }

            return new ScopeDto
            {
                Id = scope.Id,
                Name = scope.Name,
                Description = scope.Description,
                DisplayName = scope.DisplayName,
                Resources = scope.Resources != null ? JsonSerializer.Deserialize<List<string>>(scope.Resources) ?? [] : [],
                Claims = claims
            };
        }
        throw new InvalidOperationException("Invalid scope type.");
    }
}