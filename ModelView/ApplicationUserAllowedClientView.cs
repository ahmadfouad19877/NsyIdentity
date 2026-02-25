namespace IdentityServer.ModelView;

public class ApplicationUserAllowedClientView
{
    public string ClientId { get; set; }
    
    
    public string UserID { get; set; }

    public bool IsEnabled { get; set; }
}