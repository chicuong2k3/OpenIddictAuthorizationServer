using AspNetCoreHero.ToastNotification;
using AspNetCoreHero.ToastNotification.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using OpenIddictAuthorizationServer.Persistence;
using OpenIddictAuthorizationServer.Services;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.AddMemoryCache();
builder.Services.AddControllers();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
    // Register the entity sets needed by OpenIddict.
    // Note: use the generic overload if you need to replace the default OpenIddict entities.
    options.UseOpenIddict();
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedEmail = true;
    options.User.RequireUniqueEmail = true;
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;

    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;

})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromMinutes(15);
});

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        // Configure OpenIddict to use the Entity Framework Core stores and models.
        // Note: call ReplaceDefaultEntities() to replace the default entities.
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
     .AddServer(options =>
     {
         // Use this only for testing purpose.
         options.DisableAccessTokenEncryption();

         // Enable endpoints.
         options
            .SetAuthorizationEndpointUris(builder.Configuration["OpenIddictUris:AuthorizationEndpointUri"] ?? throw new ArgumentNullException("OpenIddictUris:AuthorizationEndpointUri is not defined."))
            .SetTokenEndpointUris(builder.Configuration["OpenIddictUris:TokenEndpointUri"] ?? throw new ArgumentNullException("OpenIddictUris:TokenEndpointUri is not defined."))
            .SetAccessTokenLifetime(TimeSpan.FromHours(1))
            .SetIdentityTokenLifetime(TimeSpan.FromHours(1))
            .SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(5))
            .SetRefreshTokenLifetime(TimeSpan.FromDays(7))
            .SetEndSessionEndpointUris(builder.Configuration["OpenIddictUris:EndSessionEndpointUri"] ?? throw new ArgumentNullException("OpenIddictUris:EndSessionEndpointUri is not defined."))
            .SetUserInfoEndpointUris(builder.Configuration["OpenIddictUris:UserInfoEndpointUri"] ?? throw new ArgumentNullException("OpenIddictUris:UserInfoEndpointUri is not defined."))
            .SetIntrospectionEndpointUris(builder.Configuration["OpenIddictUris:IntrospectionEndpointUri"] ?? throw new ArgumentNullException("OpenIddictUris:IntrospectionEndpointUri is not defined."))
            .SetRevocationEndpointUris(builder.Configuration["OpenIddictUris:RevocationEndpointUri"] ?? throw new ArgumentNullException("OpenIddictUris:RevocationEndpointUri is not defined."));

         // Enable flows.
         options.AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange()
            .AllowRefreshTokenFlow();

         // Register the signing and encryption credentials.
         options.AddDevelopmentEncryptionCertificate()
                .AddDevelopmentSigningCertificate();

         // Register the ASP.NET Core host and configure the ASP.NET Core options.
         options.UseAspNetCore()
                .EnableAuthorizationEndpointPassthrough()
                .EnableTokenEndpointPassthrough()
                .EnableEndSessionEndpointPassthrough()
                .EnableUserInfoEndpointPassthrough();

     })
     .AddValidation(options =>
     {
         options.UseLocalServer();
         options.UseAspNetCore();
     })
     .AddClient(options =>
     {
         options
            .AllowAuthorizationCodeFlow();
     });

builder.Services.AddAuthentication(options =>
{
    options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
    {
        options.ClientId = builder.Configuration["Authentication:Google:ClientId"] ?? throw new InvalidOperationException("Google ClientId is not configured.");
        options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"] ?? throw new InvalidOperationException("Google ClientSecret is not configured.");
        options.CallbackPath = builder.Configuration["Authentication:Google:CallbackPath"] ?? throw new InvalidOperationException("Google CallbackPath is not configured.");
        options.SignInScheme = IdentityConstants.ExternalScheme;
        options.SaveTokens = true;
        options.Scope.Add("email");
        options.Scope.Add("profile");
        options.ClaimActions.MapJsonKey("picture", "picture");
    })
    .AddFacebook(FacebookDefaults.AuthenticationScheme, options =>
    {
        options.AppId = builder.Configuration["Authentication:Facebook:AppId"] ?? throw new InvalidOperationException("Facebook AppId is not configured.");
        options.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"] ?? throw new InvalidOperationException("Facebook AppSecret is not configured.");
        options.CallbackPath = builder.Configuration["Authentication:Facebook:CallbackPath"] ?? throw new InvalidOperationException("Facebook CallbackPath is not configured.");
        options.SignInScheme = IdentityConstants.ExternalScheme;
        options.SaveTokens = true;
        options.Scope.Add("email");
        options.Scope.Add("public_profile");
        options.ClaimActions.MapJsonKey("picture", "picture");
    })
    .AddJwtBearer(options =>
    {
        var issuer = builder.Configuration["Authentication:JwtBearer:Issuer"]
            ?? throw new InvalidOperationException("JwtBearer Authority is not configured.");
        options.Authority = issuer;
        options.RequireHttpsMetadata = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            NameClaimType = Claims.Name,
            RoleClaimType = Claims.Role
        };
    });

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/login";
    options.LogoutPath = "/logout";
    options.AccessDeniedPath = "/access-denied";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.MaxAge = TimeSpan.FromDays(1);
    options.SlidingExpiration = true;
});

builder.Services.AddAuthorization();

builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<IEmailService, MockEmailService>();

builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("ResetPassword", opt =>
    {
        opt.PermitLimit = 5;
        opt.Window = TimeSpan.FromMinutes(10);
        opt.QueueLimit = 0;
    });
});

// Add Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "OpenIddict Authorization Server API", Version = "v1" });

    c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            AuthorizationCode = new OpenApiOAuthFlow
            {
                AuthorizationUrl = new Uri("/authorize", UriKind.Relative),
                TokenUrl = new Uri("/token", UriKind.Relative),
                Scopes = new Dictionary<string, string>
                {
                    { Scopes.OfflineAccess, "Offline access" },
                    { Scopes.OpenId, "Open ID" },
                    { Scopes.Email, "Email address" },
                    { Scopes.Profile, "User profile" },
                    { Scopes.Roles, "User roles" }
                }
            }
        }
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "oauth2"
                }
            },
            [
                Scopes.OfflineAccess,
                Scopes.OpenId,
                Scopes.Email,
                Scopes.Profile,
                Scopes.Roles
            ]
        }
    });
});

builder.Services.AddNotyf(config =>
{
    config.DurationInSeconds = 2;
    config.IsDismissable = true;
    config.Position = NotyfPosition.TopRight;
});



var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "OpenIddict Authorization Server API V1");
        c.OAuthClientId("swagger");
        c.OAuthClientSecret("swagger_secret");
        c.OAuthUsePkce();
        c.OAuthScopeSeparator(" ");
    });
}

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var logger = services.GetRequiredService<ILogger<DbInitializer>>();
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await dbContext.Database.EnsureDeletedAsync();
    await dbContext.Database.EnsureCreatedAsync();
    await DbInitializer.InitializeAsync(dbContext, services, logger);
}


// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseNotyf();

app.UseHttpsRedirection();
app.UseRateLimiter();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();
app.MapControllers();

app.Run();
