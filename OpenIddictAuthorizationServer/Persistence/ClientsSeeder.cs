using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddictAuthorizationServer.Persistence;

public class ClientsSeeder
{
    private readonly IServiceProvider _serviceProvider;

    public ClientsSeeder(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task AddScopesAsync()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor { Name = "email", DisplayName = "Email address" });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor { Name = "offline_access", DisplayName = "Offline access" });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor { Name = "profile", DisplayName = "User profile" });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor { Name = "openid", DisplayName = "Open ID" });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor { Name = "roles", DisplayName = "User roles" });

        var existingScope = await scopeManager.FindByNameAsync("api");
        if (existingScope == null)
        {
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "api",
                DisplayName = "Access to the API",
                Resources =
                {
                    "resource_server"
                }
            });
        }

    }

    public async Task AddClientsAsync()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();

        var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var client = await applicationManager.FindByClientIdAsync(SampleClient.ClientId);

        if (client == null)
        {
            await applicationManager.CreateAsync(new()
            {
                ClientId = SampleClient.ClientId,
                ClientSecret = SampleClient.ClientSecret,
                DisplayName = SampleClient.ClientDisplayName,
                ConsentType = ConsentTypes.Explicit,
                RedirectUris =
                {
                    new Uri("https://localhost:9090/signin-oidc")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://localhost:9090/signout-callback-oidc")
                },
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
                    Permissions.Scopes.Roles,
                    $"{Permissions.Prefixes.Scope}api"
                },
                Requirements =
                {
                }
            });
        }


    }
}
