namespace OpenIddictAuthorizationServer.Services;

public class MockEmailService : IEmailService
{
    public Task<bool> SendEmailAsync(string from, string to, string subject, string? text, string? html)
    {
        Console.WriteLine($"Sending email from {from} to {to} with subject '{subject}'");
        Console.WriteLine($"Text: {text}");
        Console.WriteLine($"HTML: {html}");
        return Task.FromResult(true);
    }
}
