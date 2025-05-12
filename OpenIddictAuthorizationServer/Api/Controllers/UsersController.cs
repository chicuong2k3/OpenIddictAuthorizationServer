using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddictAuthorizationServer.Api.Dtos;
using OpenIddictAuthorizationServer.Api.Requests;
using OpenIddictAuthorizationServer.Persistence;

namespace OpenIddictAuthorizationServer.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "admin")]
public class UsersController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;

    public UsersController(
        UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
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
}
