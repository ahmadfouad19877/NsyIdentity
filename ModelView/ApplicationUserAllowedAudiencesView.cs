namespace IdentityServer.ModelView;

public class ApplicationUserAllowedAudiencesView
{
    public Guid? Id { get; set; }
    public string OldAudiences { get; set; }
    public string Audiences { get; set; }
}