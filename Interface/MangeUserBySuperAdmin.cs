using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Interface;

public class MangeUserBySuperAdmin:IMangeUserBySuperAdmin
{
    
    private readonly UserManager<ApplicationUser> _manager;

    public MangeUserBySuperAdmin(UserManager<ApplicationUser> manager)
    {
        _manager = manager;
    }

    public async Task<IdentityResult> RegisterNewUser(ApplicationUserRegisterView UserRegisterView)
    {
       
        var NewUser = new ApplicationUser
        {
            UserName = UserRegisterView.UserName,
            PhoneNumber=UserRegisterView.UserName,
            PhoneNumberConfirmed = true
        };
        var result = await _manager.CreateAsync(NewUser, UserRegisterView.Password);
        return result;
    }

    public async Task<IdentityResult> AddNewAdmin(ApplicationAdminUserView UserRegisterView)
    {
        var NewUser = new ApplicationUser
        {
            UserName = UserRegisterView.UserName,
            PhoneNumber=UserRegisterView.UserName,
            PhoneNumberConfirmed = true
        };
        var result = await _manager.CreateAsync(NewUser);
        return result;
    }
}