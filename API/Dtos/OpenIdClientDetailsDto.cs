namespace IdentityServerNSY.API.Dtos;

/// <summary>
/// تفاصيل عميل OpenIddict
/// OpenIddict client details
/// </summary>
public class OpenIdClientDetailsDto
{
    /// <summary>
    /// معرف العميل
    /// Client id
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// الاسم الظاهر
    /// Display name
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// نوع العميل داخل OpenIddict (Public / Confidential)
    /// OpenIddict client type
    /// </summary>
    public string? ClientType { get; set; }

    /// <summary>
    /// نوعه المنطقي داخل مشروعك
    /// Logical type in your system (PublicClient / ServerClient / MachineClient)
    /// </summary>
    public string? AppType { get; set; }

    /// <summary>
    /// السكوبات المسموحة
    /// Allowed scopes
    /// </summary>
    public List<string> Scopes { get; set; } = new();

    /// <summary>
    /// روابط الإرجاع (فقط للـ Public Clients)
    /// Redirect URIs (only for public clients)
    /// </summary>
    public List<string> RedirectUris { get; set; } = new();

    /// <summary>
    /// هل هذا العميل يملك صلاحية introspection
    /// Whether this client has introspection permission
    /// </summary>
    public bool AllowIntrospection { get; set; }

    /// <summary>
    /// هل يستخدم client credentials (Machine-to-Machine)
    /// Whether this client uses client credentials grant
    /// </summary>
    public bool IsMachineClient { get; set; }

    /// <summary>
    /// هل هذا Public Client (Login / PKCE)
    /// Whether this is a public client
    /// </summary>
    public bool IsPublicClient { get; set; }

    /// <summary>
    /// تاريخ الإنشاء (إذا توفر)
    /// Creation date if available
    /// </summary>
    public DateTimeOffset? CreatedAt { get; set; }
}