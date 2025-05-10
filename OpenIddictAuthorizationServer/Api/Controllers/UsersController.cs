using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using OpenIddictAuthorizationServer.Api.Dtos;
using OpenIddictAuthorizationServer.Api.Requests;
using OpenIddictAuthorizationServer.Models;
using OpenIddictAuthorizationServer.Persistence;
using OpenIddictAuthorizationServer.Services;
using System.Web;

namespace OpenIddictAuthorizationServer.Api.Controllers;

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
    public async Task<IActionResult> GetUsers(
        [FromQuery] string search,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10)
    {
        var users = _userManager.Users;

        if (!string.IsNullOrWhiteSpace(search))
        {
            users = users.Where(u => (!string.IsNullOrEmpty(u.Email) && u.Email.ToLower().Contains(search.ToLower()))
                || (!string.IsNullOrEmpty(u.UserName) && u.UserName.ToLower().Contains(search.ToLower())));
        }

        users = users.OrderBy(u => u.Email)
            .Skip((page - 1) * pageSize)
                    .Take(pageSize);

        var totalRecords = await _userManager.Users.CountAsync();
        var userDtos = await Task.WhenAll(users.Select(u => u.MapToDtoAsync(_userManager)));

        return Ok(new PaginationResponse<UserDto>()
        {
            PageNumber = page,
            PageSize = pageSize,
            TotalRecords = totalRecords,
            TotalPages = (int)Math.Ceiling((double)totalRecords / pageSize),
            Items = userDtos.ToList()
        });
    }

    [HttpGet("{email}")]
    public async Task<IActionResult> GetUser(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return NotFound(new { errorMessage = $"User with email '{email}' not found." });
        }

        return Ok(await user.MapToDtoAsync(_userManager));
    }

    [HttpPut("{email}")]
    public async Task<IActionResult> UpdateUser(string email, [FromBody] UpdateUserRequest request)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return NotFound(new { errorMessage = $"User with email '{email}' not found." });
        }

        user.Picture = request.Picture;
        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }

        return Ok(await user.MapToDtoAsync(_userManager));
    }

    [HttpDelete("{email}")]
    public async Task<IActionResult> DeleteUser(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return NotFound(new { errorMessage = $"User with email '{email}' not found." });
        }

        var result = await _userManager.DeleteAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });
        }
        return NoContent();
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
