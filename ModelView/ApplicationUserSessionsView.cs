namespace IdentityServer.ModelView;

public class ApplicationUserSessionsView
{
    public Guid Id { get; set; }
    
    public string UserId { get; set; }
    
    public string ClientId { get; set; }
    
    public string DeviceId { get; set; }
    
    public string? DeviceName { get; set; }
    
    public string? Platform { get; set; }
    
    public string? UserAgent { get; set; }
    
    public string? TokenId { get; set; }
    
    public bool IsRevoked { get; set; }
    
}