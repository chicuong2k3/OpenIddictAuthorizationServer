using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddictAuthorizationServer.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictAuthorizationServer.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ApplicationsController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applicationManager;

    public ApplicationsController(IOpenIddictApplicationManager applicationManager)
    {
        _applicationManager = applicationManager;
    }

    //[HttpGet]
    //[Authorize(Roles = "Admin")]
    //public async Task<IActionResult> GetApplications()
    //{
    //    var applications = new List<OpenIddictApplicationDescriptor>();
    //    await foreach (var application in _applicationManager.ListAsync())
    //    {
    //        applications.Add(new OpenIddictApplicationDescriptor
    //        {
    //            DisplayName = application.DisplayName,
    //        });
    //    }
    //    return Ok(applications);
    //}

    [HttpPost]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> CreateApplication([FromBody] CreateApplicationRequest request)
    {
        var application = new OpenIddictApplicationDescriptor
        {
            ClientId = request.ClientId,
            ClientSecret = request.ClientSecret,
            DisplayName = request.DisplayName,
            RedirectUris = { new Uri(request.RedirectUri) },
            PostLogoutRedirectUris = { new Uri(request.PostLogoutRedirectUri) },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.EndSession,
                Permissions.Endpoints.Introspection,
                Permissions.Endpoints.Revocation,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                $"{Permissions.Prefixes.Scope}openid",
                $"{Permissions.Prefixes.Scope}offline_access",
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles
            }
        };
        await _applicationManager.CreateAsync(application);
        return Ok(new { application.ClientId, application.DisplayName });
    }

    [HttpDelete("{clientId}")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> DeleteApplication(string clientId)
    {
        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            return NotFound();
        }
        await _applicationManager.DeleteAsync(application);
        return Ok();
    }
}
