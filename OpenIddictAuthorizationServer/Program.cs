using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
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
    options.DefaultChallengeScheme = IdentityConstants.ExternalScheme;
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
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.MaxAge = TimeSpan.FromDays(1);
    options.SlidingExpiration = true;
});

builder.Services.AddScoped<AuthService>();
builder.Services.AddSingleton<ClientsSeeder>();

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
builder.Services.AddSwaggerGen();


var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "OpenIddict Authorization Server API V1");
    });
}

using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<ClientsSeeder>();
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await dbContext.Database.EnsureDeletedAsync();
    await dbContext.Database.EnsureCreatedAsync();
    await seeder.AddScopesAsync();
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
app.UseRateLimiter();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();
app.MapControllers();

app.Run();
