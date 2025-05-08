using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddictAuthorizationServer.Persistence;
using OpenIddictAuthorizationServer.Services;

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

})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

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
            .SetAuthorizationEndpointUris("/authorize")
            .SetTokenEndpointUris("/token")
            .SetAccessTokenLifetime(TimeSpan.FromHours(1))
            .SetIdentityTokenLifetime(TimeSpan.FromHours(1))
            .SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(5))
            .SetRefreshTokenLifetime(TimeSpan.FromDays(7))
            .SetEndSessionEndpointUris("/logout")
            .SetUserInfoEndpointUris("/userinfo")
            .SetIntrospectionEndpointUris("/introspect")
            .SetRevocationEndpointUris("/revoke");

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
    });

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/login";
    options.LogoutPath = "/logout";
    options.AccessDeniedPath = "/access-denied";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.MaxAge = TimeSpan.FromDays(1);
    options.SlidingExpiration = true;
});

builder.Services.AddScoped<AuthService>();
builder.Services.AddSingleton<ClientsSeeder>();

builder.Services.AddScoped<IEmailService, MockEmailService>();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<ClientsSeeder>();
    seeder.AddScopesAsync().GetAwaiter();
    await seeder.AddClientsAsync();
}


// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();
app.MapControllers();

app.Run();
