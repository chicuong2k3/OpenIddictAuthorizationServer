namespace OpenIddictAuthorizationServer.Services;

public interface ISmsService
{
    Task<bool> SendSmsAsync(string fromPhoneNumber, string toPhoneNumber, string message);
}
