using AspNetCoreHero.ToastNotification.Abstractions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using OpenIddictAuthorizationServer.Persistence;
using OpenIddictAuthorizationServer.Services;
using System.ComponentModel.DataAnnotations;

namespace OpenIddictAuthorizationServer.Pages;

public class ResetPasswordModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuthService _authService;
    private readonly IConfiguration _configuration;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ILogger<ResetPasswordModel> _logger;
    private readonly INotyfService _notifyService;

    public ResetPasswordModel(
        UserManager<ApplicationUser> userManager,
        AuthService authService,
        IConfiguration configuration,
        IOpenIddictApplicationManager applicationManager,
        ILogger<ResetPasswordModel> logger,
        INotyfService notifyService)
    {
        _userManager = userManager;
        _authService = authService;
        _configuration = configuration;
        _applicationManager = applicationManager;
        _logger = logger;
        _notifyService = notifyService;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new InputModel();

    public string ErrorMessage { get; set; } = string.Empty;

    public class InputModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [Display(Name = "New password")]
        public string NewPassword { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("NewPassword", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required]
        public string Token { get; set; } = string.Empty;

        public string? ReturnUrl { get; set; }
    }

    public IActionResult OnGet(string? token = null, string? email = null, string? returnUrl = null)
    {
        if (token == null || email == null)
        {
            return RedirectToPage("/Login");
        }

        Input = new InputModel
        {
            Email = email,
            Token = token,
            ReturnUrl = returnUrl
        };

        return Page();
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
            ErrorMessage = "Failed to reset your password. Please verify your information and try again.";
            return Page();
        }

        var result = await _userManager.ResetPasswordAsync(user, Input.Token, Input.NewPassword);

        if (result.Succeeded)
        {
            _logger.LogInformation("Password reset successful for user {Email}", Input.Email);
            var authorizationEndpointUri = _configuration["OpenIddictUris:AuthorizationEndpointUri"]
                        ?? throw new ArgumentNullException("OpenIddictUris:AuthorizationEndpointUri is not defined.");

            if (!await _authService.CheckReturnUrlAsync(Input.ReturnUrl ?? string.Empty, authorizationEndpointUri, _applicationManager))
            {
                _logger.LogWarning("Invalid ReturnUrl: {ReturnUrl}", Input.ReturnUrl);
                TempData["SuccessMessage"] = "Password reset successfully! You can now login with your new password.";
                return Redirect("/login");
            }

            _notifyService.Success("Password reset successfully! You can now login with your new password.");

            return Redirect($"/login?ReturnUrl={Input.ReturnUrl}");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        _logger.LogWarning("Password reset failed for {Email}: {Errors}", Input.Email,
            string.Join(", ", result.Errors.Select(e => e.Description)));

        ErrorMessage = "Failed to reset your password. Please verify your information and try again.";
        return Page();
    }
}