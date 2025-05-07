using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
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
    private readonly ILogger<ExternalLoginModel> _logger;

    public ExternalLoginModel(
        IOpenIddictApplicationManager applicationManager,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        AuthService authService,
        ILogger<ExternalLoginModel> logger)
    {
        _applicationManager = applicationManager;
        _userManager = userManager;
        _signInManager = signInManager;
        _authService = authService;
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
            try
            {
                var decodedReturnUrl = HttpUtility.UrlDecode(ReturnUrl);
                if (!Uri.TryCreate(decodedReturnUrl, UriKind.Relative, out var returnUri) ||
                    !decodedReturnUrl.StartsWith("/connect/authorize", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("Invalid ReturnUrl: {ReturnUrl}", ReturnUrl);
                    return Redirect("/login");
                }

                var absoluteUri = new Uri(new Uri("https://dummy-base"), ReturnUrl);
                var returnQueryParams = QueryHelpers.ParseQuery(absoluteUri.Query);
                if (returnQueryParams.TryGetValue("client_id", out var clientId) &&
                    returnQueryParams.TryGetValue("redirect_uri", out var redirectUri))
                {
                    var client = await _applicationManager.FindByClientIdAsync(clientId!);
                    if (client == null || !await _applicationManager.ValidateRedirectUriAsync(client, redirectUri!))
                    {
                        _logger.LogWarning("Invalid redirect_uri: {RedirectUri} for client: {ClientId}", redirectUri, clientId);
                        return Redirect("/login");
                    }

                    queryParams["returnUrl"] = ReturnUrl;
                }
                else
                {
                    _logger.LogWarning("Missing client_id or redirect_uri in ReturnUrl: {ReturnUrl}", ReturnUrl);
                    return Redirect("/login");
                }
            }
            catch
            {
                _logger.LogError("Invalid returnUrl: {ReturnUrl}", ReturnUrl);
                return Redirect("/login");
            }
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
        var returnUrl = queryParams.ContainsKey("returnUrl") ? queryParams["returnUrl"] : "/";

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

        // Check for MFA
        if (await _userManager.GetTwoFactorEnabledAsync(user))
        {
            //queryParams["email"] = email;
            //var queryString = QueryString.Create(queryParams);
            //var mfaUrl = $"/mfa{queryString}";
            //return Redirect(mfaUrl);
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

        await _signInManager.SignInAsync(user, isPersistent: true);
        return Redirect(returnUrl!);
    }

    private bool IsValidProvider(string? provider)
    {
        return !string.IsNullOrEmpty(provider) && SupportedProviders.Contains(provider);
    }
}
