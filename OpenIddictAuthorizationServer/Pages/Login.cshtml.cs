using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Abstractions;
using OpenIddictAuthorizationServer.Persistence;
using System.ComponentModel.DataAnnotations;
using System.Web;

namespace OpenIddictAuthorizationServer.Pages;

public class LoginModel : PageModel
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public LoginModel(
        IOpenIddictApplicationManager applicationManager,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager)
    {
        _applicationManager = applicationManager;
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Error { get; set; }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ErrorMessage { get; set; }

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        public bool RememberMe { get; set; }
    }

    public async Task OnGetAsync()
    {
        if (!string.IsNullOrEmpty(Error))
        {
            ErrorMessage = HttpUtility.UrlDecode(Error);
        }

        if (!string.IsNullOrEmpty(ReturnUrl))
        {
            var decodedReturnUrl = HttpUtility.UrlDecode(ReturnUrl);
            if (!Uri.TryCreate(decodedReturnUrl, UriKind.Relative, out var returnUri) ||
                !decodedReturnUrl.StartsWith("/connect/authorize", StringComparison.OrdinalIgnoreCase))
            {
                ErrorMessage = "Invalid redirect URL";
                ReturnUrl = null;
                return;
            }

            var absoluteUri = new Uri(new Uri("https://dummy-base"), decodedReturnUrl);
            var query = QueryHelpers.ParseQuery(absoluteUri.Query);
            if (query.TryGetValue("client_id", out var clientId) &&
                query.TryGetValue("redirect_uri", out var redirectUri))
            {
                var client = await _applicationManager.FindByClientIdAsync(clientId!);
                if (client == null || !await _applicationManager.ValidateRedirectUriAsync(client, redirectUri!))
                {
                    ErrorMessage = "Invalid redirect URL";
                    ReturnUrl = null;
                }
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
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return Page();
        }

        var loginSuccess = await _userManager.CheckPasswordAsync(user, Input.Password);

        if (!loginSuccess)
        {
            ErrorMessage = "Invalid email or password.";
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
