using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityServer.Models;

public class ApplicationUserSessions
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [Required]
    public string UserId { get; set; }
   
    [ForeignKey(nameof(UserId))]
    public ApplicationUser User { get; set; }

    [Required]
    public string ClientId { get; set; }
    
    [Required]
    public string DeviceId { get; set; } = default!;
    
    public string? DeviceName { get; set; } = default!;
    
    public string? Platform { get; set; } = default!;
    
    
    public string? IpAddress { get; set; } = default!;
    
    
    public string? UserAgent { get; set; } = default!;
    
    public string? TokenId { get; set; } = default!;
    
    public bool IsActive { get; set; } = true;
    public bool IsRevoked { get; set; } = false;
    
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime LastSeenAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? RevokedAt { get; set; }
}
/*
 * Id (Guid) PK
   UserId (string / Guid)
   ClientId (string)           // azp
   DeviceId (string)           // GUID من التطبيق
   DeviceName (string)
   Platform (string)           // iOS / Android / Web
   IpAddress (string)
   UserAgent (string)
   RefreshTokenId (string)     // OpenIddictToken.Id
   CreatedAt (DateTime)
   LastSeenAt (DateTime)
   IsRevoked (bool)
   RevokedAt (DateTime?)
*/