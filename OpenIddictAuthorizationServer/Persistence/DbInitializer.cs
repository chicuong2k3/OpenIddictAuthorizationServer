using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Text.Json;

namespace OpenIddictAuthorizationServer.Persistence;

public class DbInitializer
{
    public static async Task InitializeAsync(
        ApplicationDbContext context,
        IServiceProvider serviceProvider,
        ILogger<DbInitializer>? logger = null)
    {
        try
        {
            if (!await context.ClaimTypes.AnyAsync())
            {
                ClaimType[] reservedClaims =
                [
                    new ClaimType
                {
                    Name = OpenIddict.Abstractions.OpenIddictConstants.Claims.Subject,
                    Description = "User ID",
                    IsReserved = true
                },
                new ClaimType
                {
                    Name = OpenIddict.Abstractions.OpenIddictConstants.Claims.Email,
                    Description = "Email address",
                    IsReserved = true
                },
                new ClaimType
                {
                    Name = OpenIddict.Abstractions.OpenIddictConstants.Claims.EmailVerified,
                    Description = "Email verification status",
                    IsReserved = true
                },
                new ClaimType
                {
                    Name = OpenIddict.Abstractions.OpenIddictConstants.Claims.Name,
                    Description = "Username",
                    IsReserved = true
                },
                new ClaimType
                {
                    Name = OpenIddict.Abstractions.OpenIddictConstants.Claims.Role,
                    Description = "User roles",
                    IsReserved = true
                },
                new ClaimType
                {
                    Name = OpenIddict.Abstractions.OpenIddictConstants.Claims.GivenName,
                    Description = "First name",
                    IsReserved = true
                },
                new ClaimType
                {
                    Name = OpenIddict.Abstractions.OpenIddictConstants.Claims.FamilyName,
                    Description = "Last name",
                    IsReserved = true
                },
                new ClaimType
                {
                    Name = OpenIddict.Abstractions.OpenIddictConstants.Claims.Picture,
                    Description = "Profile picture",
                    IsReserved = true
                }
                ];
                context.ClaimTypes.AddRange(reservedClaims);
                await context.SaveChangesAsync();
                logger?.LogInformation("Seeded {Count} reserved claim types.", reservedClaims.Length);
            }

            var seeder = new ClientsAndUsersSeeder(serviceProvider);
            await seeder.SeedAsync();
            logger?.LogInformation("Database initialization completed.");
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to initialize database.");
            throw;
        }
    }

    public class ClientsAndUsersSeeder
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<ClientsAndUsersSeeder>? _logger;

        public ClientsAndUsersSeeder(
            IServiceProvider serviceProvider,
            ILogger<ClientsAndUsersSeeder>? logger = null)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        public async Task SeedAsync()
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();

            await SeedScopesAsync(scopeManager);
            await SeedRolesAsync(roleManager);
            await SeedUsersAsync(userManager, context, configuration);
            await SeedClientsAsync(applicationManager);
        }

        private async Task SeedScopesAsync(IOpenIddictScopeManager scopeManager)
        {
            var scopes = new[]
            {
                new OpenIddictScopeDescriptor
                {
                    Name = Scopes.OpenId,
                    DisplayName = "Open ID",
                    Properties =
                    {
                        {
                            Constants.ScopeClaimsKey,
                            JsonSerializer.SerializeToElement(new[] { Claims.Subject })
                        }
                    }
                },
                new OpenIddictScopeDescriptor
                {
                    Name = Scopes.Email,
                    DisplayName = "Email address",
                    Properties =
                    {
                        {
                            Constants.ScopeClaimsKey,
                            JsonSerializer.SerializeToElement(new[] { Claims.Email, Claims.EmailVerified })
                        }
                    }
                },
                new OpenIddictScopeDescriptor
                {
                    Name = Scopes.Profile,
                    DisplayName = "User profile",
                    Properties =
                    {
                        {
                            Constants.ScopeClaimsKey,
                            JsonSerializer.SerializeToElement(new[] { Claims.Name, Claims.GivenName, Claims.FamilyName, Claims.Picture })
                        }
                    }
                },
                new OpenIddictScopeDescriptor
                {
                    Name = Scopes.Roles,
                    DisplayName = "User roles",
                    Properties =
                    {
                        {
                            Constants.ScopeClaimsKey,
                            JsonSerializer.SerializeToElement(new[] { Claims.Role })
                        }
                    }
                },
                new OpenIddictScopeDescriptor
                {
                    Name = Scopes.OfflineAccess,
                    DisplayName = "Offline access"
                },
            };

            foreach (var scope in scopes)
            {
                if (!string.IsNullOrEmpty(scope.Name) && await scopeManager.FindByNameAsync(scope.Name) == null)
                {
                    await scopeManager.CreateAsync(scope);
                    _logger?.LogInformation("Seeded scope: {ScopeName}", scope.Name);
                }
            }
        }

        private async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
        {
            var roles = new[] { "admin" };
            foreach (var roleName in roles)
            {
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    var result = await roleManager.CreateAsync(new IdentityRole(roleName));
                    if (result.Succeeded)
                    {
                        _logger?.LogInformation("Seeded role: {RoleName}", roleName);
                    }
                    else
                    {
                        _logger?.LogError("Failed to seed role {RoleName}: {Errors}", roleName, string.Join(", ", result.Errors.Select(e => e.Description)));
                        throw new InvalidOperationException($"Failed to seed role {roleName}.");
                    }
                }
            }
        }

        private async Task SeedUsersAsync(
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext context,
            IConfiguration configuration)
        {
            var adminEmail = configuration["AdminUser:Email"] ?? throw new ArgumentNullException("Admin email is not configured.");
            var adminPassword = configuration["AdminUser:Password"] ?? throw new ArgumentNullException("Admin password is not configured.");

            var adminUser = new ApplicationUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                EmailConfirmed = true,
                TwoFactorEnabled = true
            };

            if (await userManager.FindByEmailAsync(adminUser.Email) == null)
            {
                var result = await userManager.CreateAsync(adminUser, adminPassword);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, "admin");

                    // Generate authenticator key
                    var authenticatorKey = await userManager.GetAuthenticatorKeyAsync(adminUser);
                    if (string.IsNullOrEmpty(authenticatorKey))
                    {
                        await userManager.ResetAuthenticatorKeyAsync(adminUser);
                        authenticatorKey = await userManager.GetAuthenticatorKeyAsync(adminUser);
                    }

                    var issuer = Constants.Issuer;
                    var qrCodeUri = $"otpauth://totp/{issuer}:{adminUser.Email}?secret={authenticatorKey}&issuer={issuer}";
                    _logger?.LogInformation("Admin user MFA setup: QR Code URI = {QrCodeUri}", qrCodeUri);

                    var claims = new[]
                    {
                        new IdentityUserClaim<string>
                        {
                            UserId = adminUser.Id,
                            ClaimType = Claims.Role,
                            ClaimValue = "admin"
                        }
                    };
                    context.UserClaims.AddRange(claims);
                    await context.SaveChangesAsync();

                    _logger?.LogInformation("Seeded admin user: {Email}", adminUser.Email);
                }
                else
                {
                    _logger?.LogError("Failed to seed admin user: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
                    throw new InvalidOperationException("Failed to seed admin user.");
                }
            }
        }

        private async Task SeedClientsAsync(IOpenIddictApplicationManager applicationManager)
        {
            var clients = new[]
            {
                new
                {
                    ClientId = "web_client",
                    ClientType = "web",
                    DisplayName = "Web Client",
                    ClientSecret = "web_client_secret",
                    RedirectUris = new[] { "https://localhost:9090/signin-oidc" },
                    PostLogoutRedirectUris = new[] { "https://localhost:9090/signout-callback-oidc" },
                    Permissions = new[]
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
                    Requirements = new string[] { }
                }
            };

            foreach (var client in clients)
            {
                if (await applicationManager.FindByClientIdAsync(client.ClientId) == null)
                {
                    var descriptor = new OpenIddictApplicationDescriptor
                    {
                        ClientId = client.ClientId,
                        ClientSecret = client.ClientSecret,
                        DisplayName = client.DisplayName,
                        ClientType = client.ClientType switch
                        {
                            "spa" => ClientTypes.Public,
                            "web" => ClientTypes.Confidential,
                            "machine" => ClientTypes.Confidential,
                            "device" => ClientTypes.Public,
                            _ => throw new InvalidOperationException("Invalid client type.")
                        },
                        ConsentType = ConsentTypes.Explicit
                    };

                    foreach (var uri in client.RedirectUris)
                        descriptor.RedirectUris.Add(new Uri(uri));
                    foreach (var uri in client.PostLogoutRedirectUris)
                        descriptor.PostLogoutRedirectUris.Add(new Uri(uri));
                    foreach (var permission in client.Permissions)
                        descriptor.Permissions.Add(permission);
                    foreach (var requirement in client.Requirements)
                        descriptor.Requirements.Add(requirement);

                    await applicationManager.CreateAsync(descriptor);
                    _logger?.LogInformation("Seeded client: {ClientId} ({ClientType})", client.ClientId, client.ClientType);
                }
            }
        }
    }
}