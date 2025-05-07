using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddictAuthorizationServer.Persistence;
using OpenIddictAuthorizationServer.Services;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace OpenIddictAuthorizationServer.Pages;

public class RegisterModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IEmailService _emailService;

    public RegisterModel(UserManager<ApplicationUser> userManager, IEmailService emailService)
    {
        _userManager = userManager;
        _emailService = emailService;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    [TempData]
    public string ErrorMessage { get; set; } = string.Empty;
    [TempData]
    public string SuccessMessage { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        [Required]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$")]
        public string Password { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
            return Page();

        var user = new ApplicationUser
        {
            UserName = Input.Email,
            Email = Input.Email
        };
        var result = await _userManager.CreateAsync(user, Input.Password);

        if (!result.Succeeded)
        {
            ErrorMessage = "User with this email already exists.";
            return Page();
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var confirmationUrl = Url.Page("/ConfirmEmail", null, new { email = user.Email, token = encodedToken }, Request.Scheme);

        var emailSent = await _emailService.SendEmailAsync("", user.Email, "", confirmationUrl, "");

        if (!emailSent)
        {
            ErrorMessage = "Failed to send confirmation email.";
            await _userManager.DeleteAsync(user);
            return Page();
        }

        SuccessMessage = "Sign up successful!";

        return RedirectToPage("/Login", new { ReturnUrl });
    }
}
