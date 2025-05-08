using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace ClientBff.Controllers;

[Route("account")]
public class AccountController : Controller
{
    [HttpGet("login")]
    public IActionResult Login(string returnUrl = "/")
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = returnUrl
        };
        return Challenge(properties, "oidc");
    }

    [HttpGet("logout")]
    public IActionResult Logout(string returnUrl = "/")
    {
        return SignOut(
            new AuthenticationProperties
            {
                RedirectUri = returnUrl ?? "/"
            },
            CookieAuthenticationDefaults.AuthenticationScheme,
            "oidc");
    }

    [HttpGet("userinfo")]
    [Authorize]
    public IActionResult GetUserInfo()
    {
        var claims = User.Claims.ToDictionary(c => c.Type, c => c.Value);
        return Ok(new { Claims = claims });
    }
}
