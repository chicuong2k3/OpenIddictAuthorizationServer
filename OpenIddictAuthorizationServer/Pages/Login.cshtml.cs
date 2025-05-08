using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Abstractions;
using OpenIddictAuthorizationServer.Persistence;
using OpenIddictAuthorizationServer.Services;
using System.ComponentModel.DataAnnotations;
using System.Web;

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
