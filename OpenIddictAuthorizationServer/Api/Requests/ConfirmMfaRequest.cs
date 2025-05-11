namespace OpenIddictAuthorizationServer.Api.Requests;

public class ConfirmMfaRequest
{
    public string TotpCode { get; set; } = string.Empty;
}
