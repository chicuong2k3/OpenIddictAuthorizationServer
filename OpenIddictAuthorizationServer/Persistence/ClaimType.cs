using System.ComponentModel.DataAnnotations;

namespace OpenIddictAuthorizationServer.Persistence;

public class ClaimType
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [MaxLength(256)]
    public string Name { get; set; } = null!;

    [MaxLength(500)]
    public string? Description { get; set; }

    public bool IsReserved { get; set; }
}
