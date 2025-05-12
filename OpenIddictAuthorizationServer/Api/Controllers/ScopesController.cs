using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddictAuthorizationServer.Api.Dtos;
using OpenIddictAuthorizationServer.Api.Requests;
using OpenIddictAuthorizationServer.Persistence;
using System.Text.Json;

namespace OpenIddictAuthorizationServer.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "admin")]
public class ScopesController : ControllerBase
{
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ApplicationDbContext _context;

    public ScopesController(
        IOpenIddictScopeManager scopeManager,
        ApplicationDbContext context)
    {
        _scopeManager = scopeManager;
        _context = context;
    }

    [HttpGet]
    public async Task<IActionResult> GetScopes([FromQuery] string search)
    {
        var scopes = await _scopeManager.ListAsync().ToListAsync();
        var scopeDtos = scopes.Select(scope => scope.MapToScopeDto());
        if (!string.IsNullOrWhiteSpace(search))
        {
            scopeDtos = scopeDtos.Where(scope => !string.IsNullOrEmpty(scope.Name) &&
                scope.Name.ToLower().Contains(search.ToLower()) ||
                                                 scope.Description?.ToLower()?.Contains(search.ToLower()) == true);
        }
        return Ok(scopeDtos);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetScope(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return BadRequest(new { errorMessage = "Scope ID cannot be empty." });
        }

        var scope = await _scopeManager.FindByIdAsync(id);
        if (scope == null)
        {
            return NotFound(new { errorMessage = $"Scope with ID '{id}' not found." });
        }

        return Ok(scope.MapToScopeDto());
    }

    [HttpPost]
    public async Task<IActionResult> CreateScope([FromBody] CreateUpdateScopeRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { errorMessage = "Scope name cannot be empty." });
        }

        request.Name = request.Name.ToLower();

        if (request.Claims != null)
        {
            if (request.Claims.Any(claim => string.IsNullOrWhiteSpace(claim)))
            {
                return BadRequest(new { errorMessage = "All claims must be non-empty strings." });
            }

            var validClaims = await _context.ClaimTypes.Select(ct => ct.Name).ToListAsync();
            var invalidClaims = request.Claims.Except(validClaims).ToList();
            if (invalidClaims.Any())
            {
                return BadRequest(new { errorMessage = $"Invalid claims: {string.Join(", ", invalidClaims)}" });
            }
        }

        var existingScope = await _scopeManager.FindByNameAsync(request.Name);
        if (existingScope != null)
        {
            return Conflict(new { errorMessage = $"Scope '{request.Name}' already exists." });
        }

        var scope = new OpenIddictEntityFrameworkCoreScope
        {
            Name = request.Name,
            Description = request.Description,
            DisplayName = request.DisplayName,
            Resources = request.Resources != null ? JsonSerializer.Serialize(request.Resources) : null,
            Properties = request.Claims != null && request.Claims.Any() ? JsonSerializer.Serialize(new Dictionary<string, JsonElement>
            {
                { Constants.ScopeClaimsKey, JsonSerializer.SerializeToElement(request.Claims) }
            })
            : null
        };

        await _scopeManager.CreateAsync(scope);
        return CreatedAtAction(nameof(GetScope), new { id = scope.Id }, scope.MapToScopeDto());
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateScope(string id, [FromBody] CreateUpdateScopeRequest request)
    {
        if (string.IsNullOrWhiteSpace(id) || request == null || string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { errorMessage = "Scope ID and name cannot be empty." });
        }

        request.Name = request.Name.ToLower();

        if (request.Claims != null)
        {
            if (request.Claims.Any(claim => string.IsNullOrWhiteSpace(claim)))
            {
                return BadRequest(new { errorMessage = "All claims must be non-empty strings." });
            }

            var validClaims = await _context.ClaimTypes.Select(ct => ct.Name).ToListAsync();
            var invalidClaims = request.Claims.Except(validClaims).ToList();
            if (invalidClaims.Any())
            {
                return BadRequest(new { errorMessage = $"Invalid claims: {string.Join(", ", invalidClaims)}" });
            }
        }

        var scope = await _scopeManager.FindByIdAsync(id) as OpenIddictEntityFrameworkCoreScope;
        if (scope == null)
        {
            return NotFound(new { errorMessage = $"Scope with ID '{id}' not found." });
        }

        scope.Name = request.Name;
        scope.Description = request.Description;
        scope.DisplayName = request.DisplayName;
        if (request.Resources != null)
        {
            scope.Resources = JsonSerializer.Serialize(request.Resources);
        }

        if (request.Claims != null && request.Claims.Any())
        {
            scope.Properties = JsonSerializer.Serialize(new Dictionary<string, JsonElement>
            {
                { Constants.ScopeClaimsKey, JsonSerializer.SerializeToElement(request.Claims) }
            });
        }

        await _scopeManager.UpdateAsync(scope);
        return Ok(scope.MapToScopeDto());
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteScope(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return BadRequest(new { errorMessage = "Scope ID cannot be empty." });
        }

        var scope = await _scopeManager.FindByIdAsync(id);
        if (scope == null)
        {
            return NotFound(new { errorMessage = $"Scope with ID '{id}' not found." });
        }

        await _scopeManager.DeleteAsync(scope);
        return NoContent();
    }


}
