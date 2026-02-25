using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace IdentityServerNSY.Models;

public class ApplicationUserAllowedClient
{
    
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    public string UserId { get; set; }

    [ForeignKey(nameof(UserId))]
    public ApplicationUser User { get; set; }

    public string ClientId { get; set; } = default!;

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? DeactivatedAtUtc { get; set; }
    public DateTime? ExpiresAtUtc { get; set; }

    public string? Note { get; set; }
}