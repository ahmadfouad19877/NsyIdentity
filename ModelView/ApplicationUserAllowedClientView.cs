namespace IdentityServer.ModelView;

public class ApplicationUserAllowedClientView
{
    
    public Guid? Id { get; set; }
    
    public string UserId { get; set; }
    
    public string ClientId { get; set; }
    
    public string? OldClientId { get; set; }
    
    public List<string> AllowedAudiences { get; set; }

    public bool IsEnabled { get; set; }
}