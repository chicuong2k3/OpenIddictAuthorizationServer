using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Microsoft.AspNetCore;
using System.Text.Json;
using System.Web;
using OpenIddictAuthorizationServer.Persistence;
using System.Text;

namespace OpenIddictAuthorizationServer.Services;

public class AuthService
{
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

    public bool ValidatePkce(string? codeChallenge, string? codeVerifier)
    {
        if (string.IsNullOrEmpty(codeChallenge) || string.IsNullOrEmpty(codeVerifier))
        {
            return false;
        }

        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        var computedChallenge = Convert.ToBase64String(challengeBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        return computedChallenge == codeChallenge;
    }
}