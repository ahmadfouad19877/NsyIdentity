namespace IdentityServer.ModelView;

public class OpenIdClientDto
{
    public string ClientId { get; set; } = default!;
    public string? DisplayName { get; set; }
    public List<string> Scopes { get; set; } = new();
    public List<string> ReturnUrls { get; set; } = new();
}