
using System.ComponentModel.DataAnnotations;

namespace IdentityServer.ModelView;

public class ApplicationEditeRoleAdminView
{
    [Required]
    public string UserName { get; set; }
    
    [Required]
    public String RoleName { get; set; }
    
    [Required]
    public String RemoveRoleName { get; set; }
}