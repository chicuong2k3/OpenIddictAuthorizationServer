using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using System.Collections.Immutable;
using OpenIddictAuthorizationServer.Persistence;
using Microsoft.AspNetCore.Authorization;
using OpenIddictAuthorizationServer.Services;
using System.IdentityModel.Tokens.Jwt;

namespace OpenIddictAuthorizationServer.Controllers;

[ApiController]
public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuthService _authService;

    private const int MaxScopesAllowed = 50;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        IOpenIddictTokenManager tokenManager,
        UserManager<ApplicationUser> userManager,
        AuthService authService)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _tokenManager = tokenManager;
        _userManager = userManager;
        _authService = authService;
    }

    [HttpGet("~/authorize")]
    [HttpPost("~/authorize")]
    [IgnoreAntiforgeryToken] // OpenID Connect uses state for CSRF protection
    public async Task<IActionResult> Authorize()
    {
        // get the OpenID Connect request, including the client_id, response_type, scope, ...
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // find the client application information in the database
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");
        // Validate redirect_uri
        if (!await _applicationManager.ValidateRedirectUriAsync(application, request.RedirectUri!))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Invalid redirect_uri."
                }));
        }

        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        var isAuthenticated = _authService.IsAuthenticated(result, request);
        // if the user is not authenticated, we need to challenge the user (redirect to the login page)
        if (!isAuthenticated)
        {
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = HttpContext.Request.Path + HttpContext.Request.QueryString
                });
        }

        var userId = result.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "Cannot find user from the token."
                }));
        }


        // MFA check
        if (await _userManager.GetTwoFactorEnabledAsync(user))
        {
            var parameters = _authService.ParseParameters(HttpContext);
            parameters["email"] = user.Email;
            var mfaUrl = $"/mfa{QueryString.Create(parameters)}";
            return Redirect(mfaUrl);
        }


        // get all requested scopes
        var requestedScopes = request.GetScopes();
        // Prevent DoS attacks
        if (requestedScopes.Count() > MaxScopesAllowed)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Too many scopes requested."
                }));
        }

        foreach (var scope in requestedScopes)
        {
            if (await _scopeManager.FindByNameAsync(scope) == null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidScope,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = $"The scope '{scope}' is not registered."
                    }));
            }
        }

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, userId)
                .SetClaim(Claims.Email, user.Email)
                .SetClaim(Claims.Name, user.UserName ?? userId)
                .SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray())
                .SetScopes(requestedScopes)
                .SetResources(await _scopeManager.ListResourcesAsync(requestedScopes).ToListAsync());

        var authorization = await _authorizationManager.CreateAsync(
            identity: identity,
            subject: userId,
            client: await _applicationManager.GetClientIdAsync(application) ?? string.Empty,
            type: AuthorizationTypes.Permanent,
            scopes: requestedScopes.ToImmutableArray()
        );

        var authorizationId = await _authorizationManager.GetIdAsync(authorization);
        identity.SetAuthorizationId(authorizationId);
        identity.SetDestinations(AuthService.GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            throw new InvalidOperationException("The specified grant type is not supported.");


        if (request.IsAuthorizationCodeGrantType())
        {
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId!);
            if (application == null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Client ID is invalid."
                    }));
            }

            // Validate redirect_uri
            if (!await _applicationManager.ValidateRedirectUriAsync(application, request.RedirectUri!))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Redirect URI is invalid."
                    }));
            }
        }

        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var isAuthenticated = _authService.IsAuthenticated(result, request);
        if (!isAuthenticated)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token request is invalid."
                }));
        }

        var userId = result.Principal?.GetClaim(Claims.Subject);
        var user = await _userManager.FindByIdAsync(userId ?? string.Empty);
        if (user == null)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "Cannot find user from the token."
                }));
        }

        var identity = new ClaimsIdentity(result.Principal!.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, userId)
            .SetClaim(Claims.Email, user.Email)
            .SetClaim(Claims.Name, user.UserName ?? userId)
            .SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray())
            .SetScopes(request.GetScopes())
            .SetResources(await _scopeManager.ListResourcesAsync(request.GetScopes()).ToListAsync());

        identity.SetDestinations(AuthService.GetDestinations);
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("~/logout")]
    [HttpPost("~/logout")]
    public async Task<IActionResult> Logout()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);

        if (!string.IsNullOrEmpty(request.PostLogoutRedirectUri))
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(request.IdTokenHint);
            var clientId = token.Audiences.FirstOrDefault();
            var application = await _applicationManager.FindByClientIdAsync(clientId!);
            if (application == null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Client ID is invalid."
                    }));
            }
            var redirectUris = await _applicationManager.GetPostLogoutRedirectUrisAsync(application);
            if (redirectUris.Contains(request.PostLogoutRedirectUri ?? string.Empty))
            {
                return SignOut(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties
                        {
                            RedirectUri = request.PostLogoutRedirectUri
                        });
            }
        }

        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            });
    }

    [HttpGet("~/userinfo")]
    [HttpPost("~/userinfo")]
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<IActionResult> GetUserInfo()
    {
        // To align with the OpenID Connect specification
        if (!User.HasScope(Scopes.OpenId))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidScope,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The openid scope is required to access the userinfo endpoint."
                }));
        }

        var user = await _userManager.FindByIdAsync(User.GetClaim(Claims.Subject) ?? string.Empty);
        if (user == null)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The account associated with the token no longer exists."
                }));

        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Subject] = user.Id
        };

        var issuer = User.GetClaim(Claims.Issuer);
        if (!string.IsNullOrEmpty(issuer))
        {
            claims[Claims.Issuer] = issuer;
        }

        var audience = User.GetClaim(Claims.Audience);
        if (!string.IsNullOrEmpty(audience))
        {
            claims[Claims.Audience] = audience;
        }

        var issuedAtClaim = User.GetClaim(Claims.IssuedAt);
        if (!string.IsNullOrEmpty(issuedAtClaim) && long.TryParse(issuedAtClaim, out var iat))
        {
            claims[Claims.IssuedAt] = iat;
        }

        var expiresAtClaim = User.GetClaim(Claims.ExpiresAt);
        if (!string.IsNullOrEmpty(expiresAtClaim) && long.TryParse(expiresAtClaim, out var exp))
        {
            claims[Claims.ExpiresAt] = exp;
        }

        if (User.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = user.Email ?? string.Empty;
            claims[Claims.EmailVerified] = user.EmailConfirmed;
        }

        if (User.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = user.UserName ?? string.Empty;
            if (user.Picture != null)
            {
                claims[Claims.Picture] = user.Picture;
            }
        }

        if (User.HasScope(Scopes.Roles))
        {
            claims[Claims.Role] = await _userManager.GetRolesAsync(user);
        }

        return Ok(claims);
    }


    [HttpPost("~/revoke")]
    public async Task<IActionResult> Revoke()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var isAuthenticated = _authService.IsAuthenticated(result, request);
        if (!isAuthenticated)
        {
            return Ok(); // Align with OpenID Connect specification
        }

        return Ok();
    }
}