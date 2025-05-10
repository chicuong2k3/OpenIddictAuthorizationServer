using OpenIddict.EntityFrameworkCore.Models;
using System.Text.Json;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictAuthorizationServer.Api.Dtos;

public class ApplicationDto
{
    public string? ClientId { get; set; }
    public string ClientType { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public List<string> RedirectUris { get; set; } = [];
    public List<string> PostLogoutRedirectUris { get; set; } = [];
    public List<string> Permissions { get; set; } = [];
}

public static class ApplicationExtensions
{
    public static ApplicationDto MapToApplicationDto(this object applicationObj)
    {
        if (applicationObj is OpenIddictEntityFrameworkCoreApplication app)
        {
            var permissions = app.Permissions != null
                    ? JsonSerializer.Deserialize<List<string>>(app.Permissions) ?? []
                    : [];

            return new ApplicationDto
            {
                ClientId = app.ClientId!,
                ClientType = app.ClientType switch
                {
                    ClientTypes.Public when permissions.Contains(Permissions.GrantTypes.DeviceCode) => "device",
                    ClientTypes.Public => "spa",
                    ClientTypes.Confidential when permissions.Contains(Permissions.GrantTypes.ClientCredentials) => "machine",
                    ClientTypes.Confidential => "web",
                    _ => "web"
                },
                DisplayName = app.DisplayName,
                RedirectUris = app.RedirectUris != null ? JsonSerializer.Deserialize<List<string>>(app.RedirectUris) ?? [] : [],
                PostLogoutRedirectUris = app.PostLogoutRedirectUris != null ? JsonSerializer.Deserialize<List<string>>(app.PostLogoutRedirectUris) ?? [] : [],
                Permissions = permissions
            };
        }
        throw new InvalidOperationException("Invalid application type.");
    }
}