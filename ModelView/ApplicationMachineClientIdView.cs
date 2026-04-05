namespace IdentityServerNSY.ModelView;

/// <summary>
/// طلب إنشاء عميل Machine-to-Machine
/// Create Machine-to-Machine client request
/// </summary>
public class ApplicationMachineClientIdView
{
    /// <summary>
    /// معرّف العميل
    /// Client id
    /// </summary>
    public string clientId { get; set; } = default!;

    /// <summary>
    /// السر السري للعميل
    /// Client secret
    /// </summary>
    public string clientSecrit { get; set; } = default!;

    /// <summary>
    /// الاسم الظاهر
    /// Display name
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// قائمة السكوبات المسموح بها
    /// Allowed scopes
    /// </summary>
    public List<string> Scopes { get; set; } = new();

    /// <summary>
    /// هل هذا العميل مسموح له استخدام introspection
    /// Whether this client can use introspection
    /// </summary>
    public bool AllowIntrospection { get; set; } = false;
}