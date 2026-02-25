using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Models;

public class ApplicationClientAllowedAudience
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public string ClientId { get; set; } = default!;
    public string Audience { get; set; } = default!;

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public string? Note { get; set; }
}