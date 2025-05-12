using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using OpenIddictAuthorizationServer.Persistence;
using OpenIddictAuthorizationServer.Services;
using System.ComponentModel.DataAnnotations;

namespace OpenIddictAuthorizationServer.Pages;

public class LoginModel : PageModel
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuthService _authService;
    private readonly IConfiguration _configuration;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public LoginModel(
        IOpenIddictApplicationManager applicationManager,
        UserManager<ApplicationUser> userManager,
        AuthService authService,
        IConfiguration configuration,
        SignInManager<ApplicationUser> signInManager)
    {
        _applicationManager = applicationManager;
        _userManager = userManager;
        _authService = authService;
        _configuration = configuration;
        _signInManager = signInManager;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty]
    public string? ErrorMessage { get; set; }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool ShowMfa { get; set; }

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        public bool RememberMe { get; set; }

        [DataType(DataType.Text)]
        public string? TotpCode { get; set; }
    }

    public async Task OnGetAsync()
    {
        if (!string.IsNullOrEmpty(ReturnUrl))
        {
            var authorizationEndpointUri = _configuration["OpenIddictUris:AuthorizationEndpointUri"]
                    ?? throw new ArgumentNullException("OpenIddictUris:AuthorizationEndpointUri is not defined.");

            if (!await _authService.CheckReturnUrlAsync(ReturnUrl, authorizationEndpointUri, _applicationManager))
            {
                ReturnUrl = null;
            }
        }
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(Input.Email);
        if (user == null || !await _userManager.CheckPasswordAsync(user, Input.Password))
        {
            ErrorMessage = "Invalid email or password.";
            return Page();
        }

        if (await _userManager.GetTwoFactorEnabledAsync(user))
        {
            ShowMfa = true;
            return Page();
        }

        await _signInManager.SignInAsync(user, new AuthenticationProperties
        {
            IsPersistent = Input.RememberMe,
            RedirectUri = ReturnUrl
        });

        return Redirect(ReturnUrl ?? "/");
    }

    public async Task<IActionResult> OnPostMfaAsync()
    {
        if (!ModelState.IsValid || string.IsNullOrEmpty(Input.TotpCode))
        {
            ErrorMessage = "Please enter a valid OTP code.";
            ShowMfa = true;
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(Input.Email);
        if (user == null)
        {
            ErrorMessage = "Invalid email address.";
            ShowMfa = true;
            return Page();
        }

        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, Input.TotpCode);

        if (!isValid)
        {
            ErrorMessage = "Invalid OTP code.";
            ShowMfa = true;
            return Page();
        }

        await _signInManager.SignInAsync(user, new AuthenticationProperties
        {
            IsPersistent = Input.RememberMe,
            RedirectUri = ReturnUrl
        });

        return Redirect(ReturnUrl ?? "/");
    }
}
