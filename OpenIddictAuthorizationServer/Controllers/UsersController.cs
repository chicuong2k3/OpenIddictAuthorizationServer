using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using OpenIddictAuthorizationServer.Models;
using OpenIddictAuthorizationServer.Persistence;
using OpenIddictAuthorizationServer.Services;
using System.Web;

namespace OpenIddictAuthorizationServer.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IEmailService _emailService;
    private readonly ILogger<UsersController> _logger;

    public UsersController(
        UserManager<ApplicationUser> userManager,
        IEmailService emailService,
        ILogger<UsersController> logger)
    {
        _userManager = userManager;
        _emailService = emailService;
        _logger = logger;
    }

    [HttpGet]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetUsers([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
    {
        var users = await _userManager.Users
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        var totalRecords = await _userManager.Users.CountAsync();

        return Ok(new PaginationResponse<UserDto>()
        {
            PageNumber = page,
            PageSize = pageSize,
            TotalRecords = totalRecords,
            TotalPages = (int)Math.Ceiling((double)totalRecords / pageSize),
            Items = users.Select(MapToDto).ToList()
        });
    }

    [HttpGet("{email}")]
    public async Task<IActionResult> GetUser(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return NotFound();
        }

        return Ok(MapToDto(user));
    }

    private UserDto MapToDto(ApplicationUser user)
    {
        return new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            UserName = user.UserName,
            PhoneNumber = user.PhoneNumber,
            Picture = user.Picture,
            Roles = _userManager.GetRolesAsync(user).Result.ToList()
        };
    }

    [HttpPut("{email}")]
    public async Task<IActionResult> UpdateUser(string email, [FromBody] UpdateUserRequest request)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return NotFound();
        }

        user.Picture = request.Picture;
        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(MapToDto(user));
    }

    [HttpDelete("{email}")]
    public async Task<IActionResult> DeleteUser(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return NotFound();
        }

        var result = await _userManager.DeleteAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }
        return Ok();
    }



    [HttpPost("request-reset-password")]
    [AllowAnonymous]
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
    [AllowAnonymous]
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
}
