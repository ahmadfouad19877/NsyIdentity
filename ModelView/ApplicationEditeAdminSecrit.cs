using System.ComponentModel.DataAnnotations;

namespace IdentityServer.ModelView;

public class ApplicationEditeAdminSecrit
{
    [Required]
    public string UserName { get; set; }
    
    public string ClientID { get; set; }
    
    
}