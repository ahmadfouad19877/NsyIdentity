using System.ComponentModel.DataAnnotations;

namespace IdentityServer.ModelView;

public class ApplicationAdminGetRoleView
{
    [Required]
    public string UserName { get; set; }
}