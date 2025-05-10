using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddictAuthorizationServer.Api.Dtos;
using OpenIddictAuthorizationServer.Api.Requests;
using System.Text.Json;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictAuthorizationServer.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ApplicationsController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private static readonly HashSet<string> ValidClientTypes = ["spa", "web", "machine", "device"];

    public ApplicationsController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager)
    {
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
    }

    [HttpGet]
    public async Task<IActionResult> GetApplications()
    {
        var applications = await _applicationManager.ListAsync().ToListAsync();
        return Ok(applications.Select(app => app.MapToApplicationDto()));
    }

    [HttpGet("{clientId}")]
    public async Task<IActionResult> GetApplication(string clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return BadRequest(new { errorMessage = "Client ID cannot be empty." });
        }

        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            return NotFound(new { errorMessage = $"Application with Client ID '{clientId}' not found." });
        }

        return Ok(application.MapToApplicationDto());
    }

    [HttpPost]
    public async Task<IActionResult> CreateApplication([FromBody] CreateUpdateApplicationRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.ClientId))
        {
            return BadRequest(new { errorMessage = "Client ID cannot be empty." });
        }

        var validationResult = ValidateApplicationRequest(request, isCreate: true);
        if (validationResult != null)
        {
            return validationResult;
        }

        var existingApplication = await _applicationManager.FindByClientIdAsync(request.ClientId);
        if (existingApplication != null)
        {
            return Conflict(new { errorMessage = $"Application with Client ID '{request.ClientId}' already exists." });
        }

        var (permissions, clientType) = await GetPermissionsAndClientTypeAsync(request);
        var application = new OpenIddictEntityFrameworkCoreApplication
        {
            ClientId = request.ClientId,
            ClientSecret = request.ClientSecret,
            DisplayName = request.DisplayName,
            RedirectUris = request.ClientType is "spa" or "web" ? JsonSerializer.Serialize(request.RedirectUris) : null,
            PostLogoutRedirectUris = JsonSerializer.Serialize(request.PostLogoutRedirectUris ?? []),
            Permissions = JsonSerializer.Serialize(permissions),
            ClientType = clientType
        };

        await _applicationManager.CreateAsync(application);
        return CreatedAtAction(nameof(GetApplication), new { clientId = application.ClientId }, application.MapToApplicationDto());
    }

    [HttpPut("{clientId}")]
    public async Task<IActionResult> UpdateApplication(string clientId, [FromBody] CreateUpdateApplicationRequest request)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return BadRequest(new { errorMessage = "Client ID cannot be empty." });
        }

        if (request == null)
        {
            return BadRequest(new { errorMessage = "Request body cannot be empty." });
        }

        var validationResult = ValidateApplicationRequest(request, isCreate: false);
        if (validationResult != null)
        {
            return validationResult;
        }

        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            return NotFound(new { errorMessage = $"Application with Client ID '{clientId}' not found." });
        }

        var (permissions, clientType) = await GetPermissionsAndClientTypeAsync(request);
        if (application is OpenIddictEntityFrameworkCoreApplication app)
        {
            app.ClientSecret = request.ClientSecret;
            app.DisplayName = request.DisplayName;
            app.RedirectUris = request.ClientType is "spa" or "web" ? JsonSerializer.Serialize(request.RedirectUris) : null;
            app.PostLogoutRedirectUris = JsonSerializer.Serialize(request.PostLogoutRedirectUris ?? []);
            app.Permissions = JsonSerializer.Serialize(permissions);
            app.ClientType = clientType;

            await _applicationManager.UpdateAsync(app);
            return Ok(app.MapToApplicationDto());
        }

        throw new InvalidOperationException("Invalid application type.");
    }

    [HttpDelete("{clientId}")]
    public async Task<IActionResult> DeleteApplication(string clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return BadRequest(new { errorMessage = "Client ID cannot be empty." });
        }

        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            return NotFound(new { errorMessage = $"Application with Client ID '{clientId}' not found." });
        }

        await _applicationManager.DeleteAsync(application);
        return NoContent();
    }

    private IActionResult? ValidateApplicationRequest(CreateUpdateApplicationRequest request, bool isCreate)
    {
        var clientType = request.ClientType.ToLower();
        if (!ValidClientTypes.Contains(clientType))
        {
            return BadRequest(new { errorMessage = $"Invalid client type. Must be one of: {string.Join(", ", ValidClientTypes)}" });
        }

        if (clientType is "spa" or "web")
        {
            if (request.RedirectUris == null || !request.RedirectUris.Any())
            {
                return BadRequest(new { errorMessage = "At least one Redirect URI is required for SPA or Web clients." });
            }
            foreach (var uri in request.RedirectUris)
            {
                if (string.IsNullOrWhiteSpace(uri) || !Uri.TryCreate(uri, UriKind.Absolute, out _))
                {
                    return BadRequest(new { errorMessage = $"Invalid Redirect URI: '{uri}'" });
                }
            }
        }
        else if (request.RedirectUris != null && request.RedirectUris.Any())
        {
            return BadRequest(new { errorMessage = "Redirect URIs are not allowed for Machine or Device clients." });
        }

        if (request.PostLogoutRedirectUris != null)
        {
            foreach (var uri in request.PostLogoutRedirectUris)
            {
                if (!string.IsNullOrWhiteSpace(uri) && !Uri.TryCreate(uri, UriKind.Absolute, out _))
                {
                    return BadRequest(new { errorMessage = $"Invalid Post Logout Redirect URI: '{uri}'" });
                }
            }
        }

        if (clientType == "spa" && !string.IsNullOrEmpty(request.ClientSecret))
        {
            return BadRequest(new { errorMessage = "SPA clients cannot have a client secret (public client)." });
        }

        if (clientType == "web" && string.IsNullOrEmpty(request.ClientSecret))
        {
            return BadRequest(new { errorMessage = "Web clients must have a client secret (confidential client)." });
        }

        if (clientType == "machine" && string.IsNullOrEmpty(request.ClientSecret))
        {
            return BadRequest(new { errorMessage = "Machine clients must have a client secret (confidential client)." });
        }

        if (isCreate && string.IsNullOrWhiteSpace(request.ClientId))
        {
            return BadRequest(new { errorMessage = "Client ID cannot be empty." });
        }

        return null;
    }

    private async Task<(List<string> Permissions, string ClientType)> GetPermissionsAndClientTypeAsync(CreateUpdateApplicationRequest request)
    {
        var clientType = request.ClientType.ToLower();
        var defaultPermissions = clientType switch
        {
            "spa" => new List<string>
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.EndSession,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.Implicit,
                Permissions.ResponseTypes.Code,
                Permissions.ResponseTypes.IdToken,
                Permissions.ResponseTypes.Token,
                $"{Permissions.Prefixes.Scope}openid",
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles
            },
            "web" => new List<string>
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.EndSession,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                $"{Permissions.Prefixes.Scope}openid",
                $"{Permissions.Prefixes.Scope}offline_access",
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles
            },
            "machine" => new List<string>
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.ClientCredentials
            },
            "device" => new List<string>
            {
                Permissions.Endpoints.DeviceAuthorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.DeviceCode,
                $"{Permissions.Prefixes.Scope}openid",
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                $"{Permissions.Prefixes.Scope}offline_access"
            },
            _ => throw new InvalidOperationException("Invalid client type.")
        };

        var permissions = request.Permissions?.Any() == true
            ? defaultPermissions.Union(request.Permissions).Distinct().ToList()
            : defaultPermissions;

        var validPermissions = new HashSet<string>
        {
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.EndSession,
            Permissions.Endpoints.Introspection,
            Permissions.Endpoints.Revocation,
            Permissions.Endpoints.DeviceAuthorization,
            Permissions.GrantTypes.AuthorizationCode,
            Permissions.GrantTypes.RefreshToken,
            Permissions.GrantTypes.Implicit,
            Permissions.GrantTypes.ClientCredentials,
            Permissions.GrantTypes.DeviceCode,
            Permissions.ResponseTypes.Code,
            Permissions.ResponseTypes.IdToken,
            Permissions.ResponseTypes.Token,
            $"{Permissions.Prefixes.Scope}openid",
            $"{Permissions.Prefixes.Scope}offline_access",
            Permissions.Scopes.Email,
            Permissions.Scopes.Profile,
            Permissions.Scopes.Roles
        };

        var scopes = await _scopeManager.ListAsync().ToListAsync();
        foreach (var scope in scopes)
        {
            var scopeName = await _scopeManager.GetNameAsync(scope);
            if (!string.IsNullOrEmpty(scopeName))
            {
                validPermissions.Add($"{Permissions.Prefixes.Scope}{scopeName}");
            }
        }

        // Validate permissions match client type
        var invalidPermissions = permissions.Except(validPermissions).ToList();
        if (invalidPermissions.Any())
        {
            throw new InvalidOperationException($"Invalid permissions: {string.Join(", ", invalidPermissions)}");
        }

        if (clientType == "spa" && permissions.Any(p => p == Permissions.GrantTypes.ClientCredentials || p == Permissions.GrantTypes.DeviceCode))
        {
            throw new InvalidOperationException("SPA clients cannot use client_credentials or device_code grant types.");
        }

        if (clientType == "machine" && permissions.Any(p => p == Permissions.GrantTypes.AuthorizationCode || p == Permissions.GrantTypes.Implicit || p == Permissions.GrantTypes.DeviceCode))
        {
            throw new InvalidOperationException("Machine clients cannot use authorization_code, implicit, or device_code grant types.");
        }

        if (clientType == "device" && permissions.Any(p => p == Permissions.GrantTypes.ClientCredentials || p == Permissions.GrantTypes.Implicit))
        {
            throw new InvalidOperationException("Device clients cannot use client_credentials or implicit grant types.");
        }

        return (permissions, clientType switch
        {
            "spa" => ClientTypes.Public,
            "web" => ClientTypes.Confidential,
            "machine" => ClientTypes.Confidential,
            "device" => ClientTypes.Public,
            _ => throw new InvalidOperationException("Invalid client type.")
        });
    }
}