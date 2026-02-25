using System.ComponentModel.DataAnnotations;

namespace IdentityServerNSY.ModelView;

public class ApplicationAdminGetRoleView
{
    [Required]
    public string UserName { get; set; }
}