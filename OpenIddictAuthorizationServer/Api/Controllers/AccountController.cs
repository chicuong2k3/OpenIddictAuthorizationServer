using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using OpenIddictAuthorizationServer.Api.Requests;
using OpenIddictAuthorizationServer.Models;
using OpenIddictAuthorizationServer.Persistence;
using OpenIddictAuthorizationServer.Services;
using QRCoder;
using System.Web;

namespace OpenIddictAuthorizationServer.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IEmailService _emailService;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        IEmailService emailService,
        ILogger<AccountController> logger)
    {
        _userManager = userManager;
        _emailService = emailService;
        _logger = logger;
    }

    [HttpPost("request-reset-password")]
    public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            return NotFound(new { errorMessage = "The email address is not associated with any account." });
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var encodedToken = HttpUtility.UrlEncode(token);
        var resetLink = $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}/ResetPassword?email={HttpUtility.UrlEncode(request.Email)}&token={encodedToken}";
        if (!string.IsNullOrEmpty(request.ReturnUrl))
        {
            resetLink += $"&returnUrl={HttpUtility.UrlEncode(request.ReturnUrl)}";
        }
        var success = await _emailService.SendEmailAsync("abc@gmail.com", request.Email, "Reset Password", resetLink, null);

        if (!success)
        {
            return StatusCode(500, new { errorMessage = "Failed to send email." });
        }
        return Ok();
    }

    [HttpPost("reset-password")]
    [EnableRateLimiting("ResetPassword")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordConfirmRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            return BadRequest("Invalid reset attempt.");
        }

        var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
        if (!result.Succeeded)
        {
            _logger.LogWarning("Password reset failed for {Email}: {Errors}", request.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
            return BadRequest("Invalid reset attempt.");
        }

        return Ok();
    }

    [HttpPost("enroll-mfa")]
    [Authorize]
    public async Task<IActionResult> EnrollMfa()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound(new { errorMessage = "User not found." });
        }

        if (user.TwoFactorEnabled)
        {
            return BadRequest(new { errorMessage = "MFA is already enabled." });
        }

        var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(authenticatorKey))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var issuer = Constants.Issuer;
        var qrCodeUri = $"otpauth://totp/{issuer}:{user.Email}?secret={authenticatorKey}&issuer={issuer}";
        // Generate QR code
        using var qrGenerator = new QRCodeGenerator();
        var qrCodeData = qrGenerator.CreateQrCode(qrCodeUri, QRCodeGenerator.ECCLevel.Q);
        var qrCode = new BitmapByteQRCode(qrCodeData);
        var qrCodeImage = qrCode.GetGraphic(20);
        var base64QrCode = Convert.ToBase64String(qrCodeImage);

        return Ok(new
        {
            QrCode = base64QrCode,
            ManualSetupCode = authenticatorKey,
            QrCodeUri = qrCodeUri
        });
    }

    [HttpPost("confirm-mfa")]
    [Authorize]
    public async Task<IActionResult> ConfirmMfa([FromBody] ConfirmMfaRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound(new { errorMessage = "User not found." });
        }

        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, request.TotpCode);

        if (!isValid)
        {
            return BadRequest(new { errorMessage = "Invalid TOTP code." });
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        _logger.LogInformation("User {Email} enabled MFA.", user.Email);
        return NoContent();
    }

    [HttpPost("disable-mfa")]
    [Authorize]
    public async Task<IActionResult> DisableMfa([FromBody] DisableMfaRequest request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound(new { errorMessage = "User not found." });
        }

        if (!user.TwoFactorEnabled)
        {
            return BadRequest(new { errorMessage = "MFA is already disabled." });
        }

        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, request.TotpCode);

        if (!isValid)
        {
            return BadRequest(new { errorMessage = "Invalid TOTP code." });
        }

        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _userManager.ResetAuthenticatorKeyAsync(user);
        _logger.LogInformation("User {Email} disabled MFA.", user.Email);
        return NoContent();
    }

}