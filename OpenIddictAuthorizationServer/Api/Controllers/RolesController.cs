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
public class RolesController : ControllerBase
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public RolesController(
        RoleManager<IdentityRole> roleManager,
        UserManager<ApplicationUser> userManager)
    {
        _roleManager = roleManager;
        _userManager = userManager;
    }

    [HttpGet]
    public async Task<IActionResult> GetRoles([FromQuery] string search)
    {
        var roles = await _roleManager.Roles.ToListAsync();
        if (!string.IsNullOrWhiteSpace(search))
        {
            roles = roles.Where(r => !string.IsNullOrEmpty(r.Name)
                && r.Name.ToLower().Contains(search.ToLower())).ToList();
        }
        return Ok(roles.Select(r => r.MapToDto()));
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetRole(string id)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { errorMessage = $"Role with ID '{id}' not found." });
        }
        return Ok(role.MapToDto());
    }

    [HttpPost]
    public async Task<IActionResult> CreateRole([FromBody] CreateUpdateRoleRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { errorMessage = "Role name cannot be empty." });
        }

        request.Name = request.Name.ToLower();

        var roleExists = await _roleManager.RoleExistsAsync(request.Name);
        if (roleExists)
        {
            return Conflict(new { errorMessage = $"Role '{request.Name}' already exists." });
        }
        var role = new IdentityRole(request.Name);
        var result = await _roleManager.CreateAsync(role);
        if (!result.Succeeded)
        {
            return BadRequest(new { errorMessage = result.Errors.Select(e => e.Description) });
        }

        return CreatedAtAction(nameof(GetRole), new { id = role.Id }, role.MapToDto());
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateRole(string id, [FromBody] CreateUpdateRoleRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { errorMessage = "Role name cannot be empty." });
        }

        request.Name = request.Name.ToLower();

        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { errorMessage = $"Role with ID '{id}' not found." });
        }
        role.Name = request.Name;
        var result = await _roleManager.UpdateAsync(role);
        if (!result.Succeeded)
        {
            return BadRequest(new { errorMessage = result.Errors.Select(e => e.Description) });
        }
        return Ok(role.MapToDto());
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteRole(string id)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { errorMessage = $"Role with ID '{id}' not found." });
        }
        var result = await _roleManager.DeleteAsync(role);
        if (!result.Succeeded)
        {
            return BadRequest(new { errorMessage = result.Errors.Select(e => e.Description) });
        }
        return NoContent();
    }

    [HttpGet("roles/{id}/users")]
    public async Task<IActionResult> GetUsers(string id)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound(new { errorMessage = $"Role with ID '{id}' not found." });
        }

        var users = await _userManager.GetUsersInRoleAsync(role.Name ?? string.Empty);
        if (users == null || !users.Any())
        {
            return NotFound(new { errorMessage = $"No users found for role '{role.Name}'." });
        }
        var userDtos = await Task.WhenAll(users.Select(u => u.MapToDtoAsync(_userManager)));
        return Ok(userDtos);
    }

    [HttpDelete("roles/{roleId}/users/{userId}")]
    public async Task<IActionResult> RemoveUserFromRole(string roleId, string userId)
    {
        var role = await _roleManager.FindByIdAsync(roleId);
        if (role == null)
        {
            return NotFound(new { errorMessage = $"Role with ID '{roleId}' not found." });
        }
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new { errorMessage = $"User with ID '{userId}' not found." });
        }
        var result = await _userManager.RemoveFromRoleAsync(user, role.Name ?? string.Empty);
        if (!result.Succeeded)
        {
            return BadRequest(new { errorMessage = result.Errors.Select(e => e.Description) });
        }

        return NoContent();
    }
}
