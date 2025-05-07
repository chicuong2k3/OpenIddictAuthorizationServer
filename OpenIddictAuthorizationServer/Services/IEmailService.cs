namespace OpenIddictAuthorizationServer.Services;

public interface IEmailService
{
    Task<bool> SendEmailAsync(string from, string to, string subject, string? text, string? html);
}
