namespace OpenIddictAuthorizationServer.Api.Requests;

public class CreateUpdateScopeRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string? DisplayName { get; set; }
    public List<string>? Resources { get; set; }
    public List<string>? Claims { get; set; }
}
