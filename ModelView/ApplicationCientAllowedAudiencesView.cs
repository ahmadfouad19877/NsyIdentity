namespace IdentityServer.ModelView;

public class ApplicationCientAllowedAudiencesView
{
    public Guid? Id { get; set; }
    public string ClientId { get; set; }
    
    public string Audiences { get; set; }
    
    public bool IsActive { get; set; }
}