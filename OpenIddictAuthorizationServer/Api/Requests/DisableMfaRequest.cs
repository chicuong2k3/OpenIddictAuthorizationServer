namespace OpenIddictAuthorizationServer.Api.Requests;

public class DisableMfaRequest
{
    public string TotpCode { get; set; } = string.Empty;
}
