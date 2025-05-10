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
using OpenIddict.EntityFrameworkCore.Models;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace OpenIddictAuthorizationServer.Controllers;

[ApiController]
public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuthService _authService;
    private readonly ApplicationDbContext _context;
    private const int MaxScopesAllowed = 50;

    private static readonly Dictionary<string, Func<ApplicationUser, Task<object?>>> ClaimMappings = new()
        {
            { Claims.Subject, user => Task.FromResult<object?>(user.Id) },
            { Claims.Email, user => Task.FromResult<object?>(user.Email) },
            { Claims.EmailVerified, user => Task.FromResult<object?>(user.EmailConfirmed) },
            { Claims.Name, user => Task.FromResult<object?>(user.UserName ?? user.Id) },
            { Claims.Picture, user => Task.FromResult<object?>(user.Picture) },
            { Claims.GivenName, user => Task.FromResult<object?>(user.FirstName) },
            { Claims.FamilyName, user => Task.FromResult<object?>(user.LastName) }
        };

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        UserManager<ApplicationUser> userManager,
        AuthService authService,
        ApplicationDbContext context)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _userManager = userManager;
        _authService = authService;
        _context = context;
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

        // Include scope-associated claims in the token
        var scopeClaims = await GetScopeClaimsAsync(requestedScopes);
        foreach (var claim in scopeClaims)
        {
            if (claim == Claims.Role)
            {
                identity.SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());
            }
            else
            {
                var claimValue = await GetClaimValueAsync(user, claim);
                if (claimValue != null)
                {
                    identity.SetClaim(claim, claimValue.ToString());
                }
            }
        }

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

        // Include scope-associated claims in the token
        var scopeClaims = await GetScopeClaimsAsync(request.GetScopes());
        foreach (var claim in scopeClaims)
        {
            if (claim == Claims.Role)
            {
                identity.SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());
            }
            else
            {
                var claimValue = await GetClaimValueAsync(user, claim);
                if (claimValue != null)
                {
                    identity.SetClaim(claim, claimValue.ToString());
                }
            }
        }

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

        var requestedScopes = User.GetScopes();
        var scopeClaims = await GetScopeClaimsAsync(requestedScopes);
        foreach (var claim in scopeClaims)
        {
            if (claim == Claims.Role)
            {
                claims[Claims.Role] = await _userManager.GetRolesAsync(user);
            }
            else
            {
                var claimValue = await GetClaimValueAsync(user, claim);
                if (claimValue != null)
                {
                    claims[claim] = claimValue;
                }
            }
        }

        return Ok(claims);
    }

    private async Task<List<string>> GetScopeClaimsAsync(IEnumerable<string> scopes)
    {
        var validClaims = await _context.ClaimTypes.Select(ct => ct.Name).ToListAsync();
        var claims = new List<string>();
        foreach (var scope in scopes)
        {
            var scopeObj = await _scopeManager.FindByNameAsync(scope);
            if (scopeObj is OpenIddictEntityFrameworkCoreScope efScope && efScope.Properties != null)
            {
                var properties = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(efScope.Properties);
                if (properties != null && properties.TryGetValue(Constants.ScopeClaimsKey, out var claimsElement))
                {
                    var scopeClaims = claimsElement.Deserialize<List<string>>();
                    if (scopeClaims != null)
                    {
                        claims.AddRange(scopeClaims.Where(c => validClaims.Contains(c)));
                    }
                }
            }
        }
        return claims.Distinct().ToList();
    }

    private async Task<object?> GetClaimValueAsync(ApplicationUser user, string claimType)
    {
        if (!await _context.ClaimTypes.AnyAsync(ct => ct.Name == claimType))
        {
            return null;
        }

        // Check reserved claim mappings
        if (ClaimMappings.TryGetValue(claimType, out var mapping))
        {
            return await mapping(user);
        }

        var userClaims = await _userManager.GetClaimsAsync(user);
        var claim = userClaims.FirstOrDefault(c => c.Type == claimType);
        if (claim != null)
        {
            return claim.Value;
        }

        return null;
    }
}