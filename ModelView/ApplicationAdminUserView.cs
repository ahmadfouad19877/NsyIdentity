using System.ComponentModel.DataAnnotations;

namespace IdentityServerNSY.ModelView;

public class ApplicationAdminUserView
{
    [Required]
    public string UserName { get; set; }

   // [Required]
   // public string Password { get; set; }
    
    [Required]
    public string ClientID { get; set; }
    
    [Required]
    public String RoleName { get; set; }
    
    
}

