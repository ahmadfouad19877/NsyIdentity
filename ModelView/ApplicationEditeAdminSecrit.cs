using System.ComponentModel.DataAnnotations;

namespace IdentityServerNSY.ModelView;

public class ApplicationEditeAdminSecrit
{
    [Required]
    public string UserName { get; set; }
    
    public string ClientID { get; set; }
    
    
}