using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;
using Microsoft.AspNetCore.WebUtilities;
using System.Web;
using Microsoft.Extensions.Logging;

namespace OpenIddictAuthorizationServer.Services;

public class AuthService
{
    private readonly ILogger<AuthService> _logger;

    public AuthService(ILogger<AuthService> logger)
    {
        _logger = logger;
    }

    public IDictionary<string, StringValues> ParseParameters(HttpContext httpContext, List<string>? excluding = null)
    {
        var parameters = httpContext.Request.HasFormContentType ?
        httpContext.Request.Form.AsQueryable() : httpContext.Request.Query.AsQueryable();

        var result = new Dictionary<string, StringValues>();
        var count = 0;

        foreach (var parameter in parameters)
        {
            if (excluding != null && excluding.Contains(parameter.Key))
                continue;

            if (parameter.Key.Length > 256 || parameter.Value.Any(v => v?.Length > 4096))
                throw new InvalidOperationException("Parameter key or value is too large.");

            result[parameter.Key] = parameter.Value;
            count++;

            if (count > 50)
                throw new InvalidOperationException("Too many parameters.");
        }

        return result;
    }

    public bool IsAuthenticated(AuthenticateResult result, OpenIddictRequest request)
    {
        if (result == null || !result.Succeeded)
        {
            return false;
        }

        if (request.MaxAge != null && result.Properties?.IssuedUtc != null)
        {
            var maxAge = TimeSpan.FromSeconds(request.MaxAge.Value);
            var expired = DateTimeOffset.UtcNow - result.Properties.IssuedUtc > maxAge;
            if (expired)
            {
                return false;
            }
        }

        return true;
    }

    public static IEnumerable<string> GetDestinations(Claim claim)
    {
        switch (claim.Type)
        {
            case Claims.Subject:
                yield return Destinations.AccessToken;
                if (claim.Subject != null && claim.Subject.HasScope(Scopes.OpenId))
                {
                    yield return Destinations.IdentityToken;
                }
                break;
            case Claims.Name:
                yield return Destinations.AccessToken;
                if (claim.Subject != null && claim.Subject.HasScope(Scopes.Profile))
                {
                    yield return Destinations.IdentityToken;
                }
                yield break;
            case Claims.Email:
                yield return Destinations.AccessToken;
                if (claim.Subject != null && claim.Subject.HasScope(Scopes.Email))
                {
                    yield return Destinations.IdentityToken;
                }
                yield break;
            case Claims.Role:
                yield return Destinations.AccessToken;
                if (claim.Subject != null && claim.Subject.HasScope(Scopes.Roles))
                {
                    yield return Destinations.IdentityToken;
                }
                yield break;
            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }

    public async Task<bool> CheckReturnUrlAsync(string returnUrl, string authorizationEndpointUri, IOpenIddictApplicationManager applicationManager)
    {
        try
        {
            var decodedReturnUrl = HttpUtility.UrlDecode(returnUrl);
            if (!decodedReturnUrl.StartsWith(authorizationEndpointUri, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("ReturnUrl does not start with {AuthorizationEndpointUri}: {ReturnUrl}", authorizationEndpointUri, returnUrl);
                return false;
            }

            var queryStartIndex = decodedReturnUrl.IndexOf('?');
            var returnQueryParams = queryStartIndex >= 0
                ? QueryHelpers.ParseQuery(decodedReturnUrl.Substring(queryStartIndex + 1))
                : new Dictionary<string, StringValues>();

            if (!returnQueryParams.TryGetValue("client_id", out var clientId) ||
                        !returnQueryParams.TryGetValue("redirect_uri", out var redirectUri) ||
                        !returnQueryParams.TryGetValue("response_type", out var responseType) ||
                        !returnQueryParams.TryGetValue("scope", out var scope))
            {
                _logger.LogWarning("Missing required OAuth parameters (client_id, redirect_uri, response_type, scope) in ReturnUrl: {ReturnUrl}", returnUrl);
                return false;
            }

            var client = await applicationManager.FindByClientIdAsync(clientId!);
            if (client == null)
            {
                _logger.LogWarning("Client not found for client_id: {ClientId}", clientId);
                return false;
            }

            if (!await applicationManager.ValidateRedirectUriAsync(client, redirectUri!))
            {
                _logger.LogWarning("Invalid redirect_uri: {RedirectUri} for client: {ClientId}", redirectUri, clientId);
                return false;
            }

            if (responseType != "code")
            {
                _logger.LogWarning("Unsupported response_type: {ResponseType} in ReturnUrl: {ReturnUrl}", responseType, returnUrl);
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to validate ReturnUrl: {ReturnUrl}", returnUrl);
            return false;
        }
    }
}