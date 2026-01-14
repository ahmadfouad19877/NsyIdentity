namespace IdentityServer.ModelView;

public class ApplicationAddClientIdView
{
    public string clientId { get; set; }
    
    public string OldclientId { get; set; }
    public string? displayName { get; set; }
    public string? redirectUri { get; set; }
    public string? Scop { get; set; }
}