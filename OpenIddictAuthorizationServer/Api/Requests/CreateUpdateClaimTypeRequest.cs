namespace OpenIddictAuthorizationServer.Api.Requests;

public class CreateUpdateClaimTypeRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
}
