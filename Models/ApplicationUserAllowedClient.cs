using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityServer.Models;

public class ApplicationUserAllowedClient
{
    
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    public string UserId { get; set; } = default!;
    [ForeignKey(nameof(UserId))]
    public ApplicationUser User { get; set; } = default!;

    public string ClientId { get; set; } = default!;

    public bool IsEnabled { get; set; } = true;
    
    
    public DateTime CreatedAt { get; set; } = DateTime.Now;
}