using ClientBff.Client.Pages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ClientBff.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public partial class TokenController : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetTokenInfo()
    {
        var accessToken = await HttpContext.GetTokenAsync("access_token");
        var refreshToken = await HttpContext.GetTokenAsync("refresh_token");
        var idToken = await HttpContext.GetTokenAsync("id_token");

        var scopes = HttpContext.User.Claims
            .Where(c => c.Type == "scopes")
            .Select(c => c.Value)
            .ToList();

        return Ok(new
        {
            Tokens = new List<TokenInfo>()
            {
                new TokenInfo
                {
                    TokenType = "Access Token",
                    TokenData = accessToken,
                },
                new TokenInfo
                {
                    TokenType = "Refresh Token",
                    TokenData = refreshToken,
                },
                new TokenInfo
                {
                    TokenType = "ID Token",
                    TokenData = idToken,
                }
            },
            Scopes = scopes
        });
    }
}