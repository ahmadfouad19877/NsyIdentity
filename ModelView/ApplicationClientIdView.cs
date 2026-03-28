namespace IdentityServerNSY.ModelView;

public class ApplicationClientIdView
{
    public string clientId { get; set; } = default!;

    public string? displayName { get; set; }

    // عربي: قائمة Redirect URIs
    // English: List of redirect URIs
    public List<string>? redirectUris { get; set; }

    public string? Scop { get; set; }
}