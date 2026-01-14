using IdentityServer.ModelView;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Interface;

public interface IMangeUserBySuperAdmin
{
    Task<IdentityResult> RegisterNewUser(ApplicationUserRegisterView UserRegisterView);
    Task<IdentityResult> AddNewAdmin(ApplicationAdminUserView UserRegisterView);
    
    //Task<IdentityResult> EditeAdminSecrite(ApplicationEditeAdminSecrit model);
    
}