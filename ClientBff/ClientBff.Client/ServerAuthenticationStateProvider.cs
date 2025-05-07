using Microsoft.AspNetCore.Components.Authorization;
using System.Net.Http.Json;
using System.Security.Claims;

namespace ClientBff.Client;

public class ServerAuthenticationStateProvider : AuthenticationStateProvider
{
    private readonly HttpClient _httpClient;

    public ServerAuthenticationStateProvider(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync("/account/userinfo");
            if (response.IsSuccessStatusCode)
            {
                var userInfo = await response.Content.ReadFromJsonAsync<UserInfo>();

                if (userInfo != null)
                {
                    var claims = userInfo.Claims.Select(kvp => new Claim(kvp.Key, kvp.Value));
                    var identity = new ClaimsIdentity(claims, "bff");
                    var user = new ClaimsPrincipal(identity);
                    return new AuthenticationState(user);
                }
            }
        }
        catch
        {

        }


        return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
    }
}

public class UserInfo
{
    public Dictionary<string, string> Claims { get; set; } = new();
}
