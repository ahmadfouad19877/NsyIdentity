using System.ComponentModel.DataAnnotations;

namespace IdentityServerNSY.ModelView;

public class ApplicationAddRoleAdminView
{
    [Required]
    public string UserName { get; set; }
    
    [Required]
    public String RoleName { get; set; }
}