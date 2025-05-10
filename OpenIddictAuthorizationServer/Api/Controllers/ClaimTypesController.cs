using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddictAuthorizationServer.Api.Dtos;
using OpenIddictAuthorizationServer.Api.Requests;
using OpenIddictAuthorizationServer.Persistence;
using System.Security.Claims;
using System.Text.Json;

namespace OpenIddictAuthorizationServer.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ClaimTypesController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private static readonly HashSet<string> ReservedClaimTypes = new()
        {
            OpenIddictConstants.Claims.Subject,
            OpenIddictConstants.Claims.Email,
            OpenIddictConstants.Claims.EmailVerified,
            OpenIddictConstants.Claims.Name,
            OpenIddictConstants.Claims.Role,
            OpenIddictConstants.Claims.GivenName,
            OpenIddictConstants.Claims.FamilyName,
            OpenIddictConstants.Claims.Picture
        };

    public ClaimTypesController(
            ApplicationDbContext context,
            IOpenIddictScopeManager scopeManager,
            UserManager<ApplicationUser> userManager)
    {
        _context = context;
        _scopeManager = scopeManager;
        _userManager = userManager;
    }

    [HttpGet]
    public async Task<IActionResult> SearchClaimTypes([FromQuery] string? search)
    {
        var query = _context.ClaimTypes.AsQueryable();
        if (!string.IsNullOrWhiteSpace(search))
        {
            query = query.Where(ct => ct.Name.ToLower().Contains(search.ToLower()));
        }

        var claimTypes = await query
            .OrderBy(ct => ct.Name)
            .Select(ct => ct.MapToDto())
            .ToListAsync();

        return Ok(claimTypes);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetClaimType(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return BadRequest(new { errorMessage = "Claim type ID cannot be empty." });
        }

        var claimType = await _context.ClaimTypes.FindAsync(id);
        if (claimType == null)
        {
            return NotFound(new { errorMessage = $"Claim type with ID '{id}' not found." });
        }

        return Ok(claimType.MapToDto());
    }

    [HttpPost]
    public async Task<IActionResult> CreateClaimType([FromBody] CreateUpdateClaimTypeRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { errorMessage = "Claim type name cannot be empty." });
        }

        request.Name = request.Name.ToLower();

        if (await _context.ClaimTypes.AnyAsync(ct => ct.Name == request.Name))
        {
            return Conflict(new { errorMessage = $"Claim type '{request.Name}' already exists." });
        }

        var claimType = new ClaimType
        {
            Name = request.Name,
            Description = request.Description,
            IsReserved = ReservedClaimTypes.Contains(request.Name)
        };

        _context.ClaimTypes.Add(claimType);
        await _context.SaveChangesAsync();

        var dto = claimType.MapToDto();

        return CreatedAtAction(nameof(GetClaimType), new { id = claimType.Id }, dto);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateClaimType(string id, [FromBody] CreateUpdateClaimTypeRequest request)
    {
        if (string.IsNullOrWhiteSpace(id) || request == null || string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { errorMessage = "Claim type ID and name cannot be empty." });
        }

        request.Name = request.Name.ToLower();

        var claimType = await _context.ClaimTypes.FindAsync(id);
        if (claimType == null)
        {
            return NotFound(new { errorMessage = $"Claim type with ID '{id}' not found." });
        }

        if (claimType.IsReserved && claimType.Name != request.Name)
        {
            return BadRequest(new { errorMessage = "Cannot change the name of a reserved claim type." });
        }

        if (claimType.Name != request.Name && await _context.ClaimTypes.AnyAsync(ct => ct.Name == request.Name))
        {
            return Conflict(new { errorMessage = $"Claim type '{request.Name}' already exists." });
        }

        if (claimType.Name != request.Name)
        {
            await UpdateScopeClaimsAsync(claimType.Name, request.Name);
            await UpdateUserClaimsAsync(claimType.Name, request.Name);
        }

        claimType.Name = request.Name;
        claimType.Description = request.Description;
        claimType.IsReserved = ReservedClaimTypes.Contains(request.Name);

        await _context.SaveChangesAsync();

        return Ok(claimType.MapToDto());
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteClaimType(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return BadRequest(new { errorMessage = "Claim type ID cannot be empty." });
        }

        var claimType = await _context.ClaimTypes.FindAsync(id);
        if (claimType == null)
        {
            return NotFound(new { errorMessage = $"Claim type with ID '{id}' not found." });
        }

        if (claimType.IsReserved)
        {
            return BadRequest(new { errorMessage = "Cannot delete a reserved claim type." });
        }

        await RemoveScopeClaimsAsync(claimType.Name);
        await RemoveUserClaimsAsync(claimType.Name);

        _context.ClaimTypes.Remove(claimType);
        await _context.SaveChangesAsync();

        return NoContent();
    }

    [HttpPost("assign-to-user")]
    public async Task<IActionResult> AssignClaimToUser([FromBody] AssignClaimRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.UserId) || string.IsNullOrWhiteSpace(request.ClaimType) || string.IsNullOrWhiteSpace(request.ClaimValue))
        {
            return BadRequest(new { errorMessage = "User ID, claim type, and claim value cannot be empty." });
        }

        if (!await _context.ClaimTypes.AnyAsync(ct => ct.Name == request.ClaimType))
        {
            return BadRequest(new { errorMessage = $"Claim type '{request.ClaimType}' does not exist." });
        }

        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user == null)
        {
            return NotFound(new { errorMessage = $"User with ID '{request.UserId}' not found." });
        }

        var existingClaims = await _userManager.GetClaimsAsync(user);
        var existingClaim = existingClaims.FirstOrDefault(c => c.Type == request.ClaimType);
        if (existingClaim != null)
        {
            await _userManager.RemoveClaimAsync(user, existingClaim);
        }

        await _userManager.AddClaimAsync(user, new Claim(request.ClaimType, request.ClaimValue));
        return NoContent();
    }

    private async Task UpdateScopeClaimsAsync(string oldName, string newName)
    {
        var scopes = await _scopeManager.ListAsync().ToListAsync();
        foreach (var scopeObj in scopes)
        {
            if (scopeObj is OpenIddictEntityFrameworkCoreScope scope && scope.Properties != null)
            {
                var properties = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(scope.Properties);
                if (properties != null && properties.TryGetValue(Constants.ScopeClaimsKey, out var claimsElement))
                {
                    var claims = claimsElement.Deserialize<List<string>>();
                    if (claims != null && claims.Contains(oldName))
                    {
                        claims.Remove(oldName);
                        claims.Add(newName);
                        properties[Constants.ScopeClaimsKey] = JsonSerializer.SerializeToElement(claims);
                        scope.Properties = JsonSerializer.Serialize(properties);
                        await _scopeManager.UpdateAsync(scope);
                    }
                }
            }
        }
    }

    private async Task RemoveScopeClaimsAsync(string claimName)
    {
        var scopes = await _scopeManager.ListAsync().ToListAsync();
        foreach (var scopeObj in scopes)
        {
            if (scopeObj is OpenIddictEntityFrameworkCoreScope scope && scope.Properties != null)
            {
                var properties = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(scope.Properties);
                if (properties != null && properties.TryGetValue(Constants.ScopeClaimsKey, out var claimsElement))
                {
                    var claims = claimsElement.Deserialize<List<string>>();
                    if (claims != null && claims.Contains(claimName))
                    {
                        claims.Remove(claimName);
                        if (claims.Any())
                        {
                            properties[Constants.ScopeClaimsKey] = JsonSerializer.SerializeToElement(claims);
                            scope.Properties = JsonSerializer.Serialize(properties);
                        }
                        else
                        {
                            scope.Properties = null;
                        }
                        await _scopeManager.UpdateAsync(scope);
                    }
                }
            }
        }
    }

    private async Task UpdateUserClaimsAsync(string oldName, string newName)
    {
        var users = await _userManager.Users.ToListAsync();
        foreach (var user in users)
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var claim = claims.FirstOrDefault(c => c.Type == oldName);
            if (claim != null)
            {
                await _userManager.RemoveClaimAsync(user, claim);
                await _userManager.AddClaimAsync(user, new Claim(newName, claim.Value));
            }
        }
    }

    private async Task RemoveUserClaimsAsync(string claimName)
    {
        var users = await _userManager.Users.ToListAsync();
        foreach (var user in users)
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var claim = claims.FirstOrDefault(c => c.Type == claimName);
            if (claim != null)
            {
                await _userManager.RemoveClaimAsync(user, claim);
            }
        }
    }
}
