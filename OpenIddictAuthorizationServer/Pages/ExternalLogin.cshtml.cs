using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using OpenIddictAuthorizationServer.Persistence;
using OpenIddictAuthorizationServer.Services;
using System.Security.Claims;
using System.Web;

namespace OpenIddictAuthorizationServer.Pages;

public class ExternalLoginModel : PageModel
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly AuthService _authService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<ExternalLoginModel> _logger;

    public ExternalLoginModel(
        IOpenIddictApplicationManager applicationManager,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        AuthService authService,
        IConfiguration configuration,
        ILogger<ExternalLoginModel> logger)
    {
        _applicationManager = applicationManager;
        _userManager = userManager;
        _signInManager = signInManager;
        _authService = authService;
        _configuration = configuration;
        _logger = logger;
    }

    [BindProperty(SupportsGet = true)]
    public string Provider { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    private static readonly HashSet<string> SupportedProviders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Facebook", "Google"
    };

    public async Task<IActionResult> OnGetAsync()
    {
        if (!IsValidProvider(Provider))
        {
            _logger.LogWarning("Invalid provider: {Provider}", Provider);
            return Redirect("/login");
        }

        // Parse returnUrl for OAuth parameters
        var queryParams = new Dictionary<string, string?>();
        if (!string.IsNullOrEmpty(ReturnUrl))
        {
            var authorizationEndpointUri = _configuration["OpenIddictUris:AuthorizationEndpointUri"]
                    ?? throw new ArgumentNullException("OpenIddictUris:AuthorizationEndpointUri is not defined.");

            if (!await _authService.CheckReturnUrlAsync(ReturnUrl, authorizationEndpointUri, _applicationManager))
            {
                _logger.LogWarning("Invalid ReturnUrl: {ReturnUrl}", ReturnUrl);
                return Redirect("/login");
            }

            queryParams["returnUrl"] = HttpUtility.UrlEncode(ReturnUrl);
        }

        var redirectUrl = Url.Page("./ExternalLogin", pageHandler: "Callback");
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(Provider, redirectUrl);
        foreach (var param in queryParams)
        {
            properties.Items[param.Key] = param.Value;
        }
        return new ChallengeResult(Provider, properties);
    }

    public async Task<IActionResult> OnGetCallbackAsync(string? remoteError = null)
    {
        if (!string.IsNullOrEmpty(remoteError))
        {
            _logger.LogWarning("Remote error from provider: {Error}", remoteError);
            return Redirect("/login");
        }

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            _logger.LogError("External login info is null.");
            return Redirect("/login");
        }

        var queryParams = info.AuthenticationProperties?.Items
            .Where(kvp => !string.IsNullOrEmpty(kvp.Key))
            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value) ?? new Dictionary<string, string?>();
        var authorizationEndpointUri = _configuration["OpenIddictUris:AuthorizationEndpointUri"]
                    ?? throw new ArgumentNullException("OpenIddictUris:AuthorizationEndpointUri is not defined.");
        var returnUrl = queryParams.ContainsKey("returnUrl") ? HttpUtility.UrlDecode(queryParams["returnUrl"]) : "/login";
        if (!string.IsNullOrEmpty(returnUrl) && !Url.IsLocalUrl(returnUrl) && !returnUrl.StartsWith(authorizationEndpointUri, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Invalid returnUrl in callback: {ReturnUrl}", returnUrl);
            return Redirect("/login");
        }

        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        var user = await _userManager.FindByEmailAsync(email ?? string.Empty);
        if (user == null)
        {
            user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                Picture = info.Principal.FindFirstValue("picture"),
                EmailConfirmed = true
            };

            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                _logger.LogError("Failed to create user: {Errors}", string.Join(", ", createResult.Errors.Select(e => e.Description)));
                return Redirect("/login");
            }

            _logger.LogInformation("Created new user with email: {Email}", email);

            var addLoginResult = await _userManager.AddLoginAsync(user, info);
            if (!addLoginResult.Succeeded)
            {
                _logger.LogError("Failed to add external login: {Errors}", string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
                return Redirect("/login");
            }

            _logger.LogInformation("Added external login for user: {Email}", email);
        }

        var signInResult = await _signInManager.ExternalLoginSignInAsync(
            info.LoginProvider,
            info.ProviderKey,
            isPersistent: true,
            bypassTwoFactor: false);

        if (!signInResult.Succeeded)
        {
            if (signInResult.IsLockedOut)
            {
                return Redirect("/login");
            }
        }

        await _signInManager.SignInAsync(user, new AuthenticationProperties
        {
            IsPersistent = true,
            RedirectUri = returnUrl
        });
        return Redirect(returnUrl!);
    }

    private bool IsValidProvider(string? provider)
    {
        return !string.IsNullOrEmpty(provider) && SupportedProviders.Contains(provider);
    }
}
